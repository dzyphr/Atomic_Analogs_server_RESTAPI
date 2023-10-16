use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use uuid::{uuid, Uuid};
use std::fs::OpenOptions;
use serde_json::{json, Value, Map};
use warp::{http, Filter};
use std::io::BufReader;
use std::fs::File;
use std::io::prelude::*;
use warp::reply::Html;
use warp::Reply;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use subprocess::{PopenConfig, Popen, Redirection};
fn json_body() -> impl Filter<Extract = (Request,), Error = warp::Rejection> + Clone {
    // When accepting a body, we want a JSON body
    // (and to reject huge payloads)...
    warp::body::content_length_limit(1024 * 1024 * 50/*mb*/).and(warp::body::json())
}

fn delete_json() -> impl Filter<Extract = (Id,), Error = warp::Rejection> + Clone {
    // When accepting a body, we want a JSON body
    // (and to reject huge payloads)...
    warp::body::content_length_limit(1024 * 1024 * 50/*mb*/).and(warp::body::json())
}

fn accepted_private_api_keys() -> Vec<&'static str>
{
    return vec![
        "PASSWORD"
    ]
}

fn accepted_public_api_keys() -> Vec<&'static str>
{
    return vec![
        "123"
    ]
}


fn private_accepted_request_types() -> Vec<&'static str>
{
    return vec![
        "publishNewOrderType"
    ]
}

fn public_accepted_request_types() -> Vec<&'static str>
{
    return vec![
        "requestEncryptedInitiation",
        "submitEncryptedResponse"

    ]
}


fn ElGamal_keypaths() -> Vec<&'static str>
{
    return vec![
        "Key0.ElGamalKey"
    ]
}

fn accountNameFromChainAndIndex(chain: String, index: usize) -> &'static str
{
    if chain == "Ergo"
    {
        let accountvec = vec![
            "basic_framework"
        ];
        return accountvec[index]
    }
    if chain == "Sepolia"
    {
        let accountvec = vec![
            "p2ENV"
        ];
        return accountvec[index]
    }
    else
    {
        return "chain not found"
    }
}

#[tokio::main]
async fn main() {
    let version =  "v0.0.1";
    let main_path  = "requests";
    let public_main_path = "publicrequests";
    let OrderTypesPath = "ordertypes";

    let storage = Storage::new();
    let storage_filter = warp::any().map(move || storage.clone());
    let bearer_private_api_key_filter = warp::header::<String>("Authorization").and_then( | auth_header: String | async move {
            if auth_header.starts_with("Bearer ")
            {
                let api_key = auth_header.trim_start_matches("Bearer ").to_string();
                if accepted_private_api_keys().contains(&api_key.as_str())
                {
                    let response = warp::reply::html("API Key Valid");
                    Ok(response)
                }
                else
                {
                    Err(warp::reject::custom(Badapikey))
                }
            }
            else
            {
                Err(warp::reject::custom(Noapikey))
            }
    });
    //add and update use the same function just differ in post and put
    let add_requests = warp::post()
        .and(warp::path(version))
        .and(warp::path(main_path))
        .and(warp::path::end())
        .and(json_body())
        .and(storage_filter.clone())
        .and(bearer_private_api_key_filter)
        .and_then(private_update_request_map);
    let update_request = warp::put() 
        .and(warp::path(version))
        .and(warp::path(main_path))
        .and(warp::path::end())
        .and(json_body())
        .and(storage_filter.clone())
        .and(bearer_private_api_key_filter)
        .and_then(private_update_request_map);
    let get_requests = warp::get()
        .and(warp::path(version))
        .and(warp::path(main_path))
        .and(warp::path::end())
        .and(storage_filter.clone())
        .and(bearer_private_api_key_filter)
        .and_then(private_get_request_map);
    let private_delete_request = warp::delete()
        .and(warp::path(version))
        .and(warp::path(main_path))
        .and(warp::path::end())
        .and(delete_json())
        .and(storage_filter.clone())
        .and(bearer_private_api_key_filter)
        .and_then(private_delete_request);
    let public_ordertypes_get_request = warp::get()
        .and(warp::path(version))
        .and(warp::path(OrderTypesPath))
        .and(warp::path::end())
        .and_then(get_ordertypes);
    let public_add_requests = warp::post()
        .and(warp::path(version))
        .and(warp::path(public_main_path))
        .and(warp::path::end())
        .and(json_body())
        .and(storage_filter.clone())
        .and_then(public_update_request_map);
    let routes = add_requests.or(get_requests).or(update_request).or(private_delete_request).or(public_ordertypes_get_request).or(public_add_requests);
    warp::serve(routes)
        .run(([127, 0, 0, 1], 3030))
        .await;
}


async fn private_delete_request(
    id: Id,
    storage: Storage,
    apikey: Html<&str>
    ) -> Result<impl warp::Reply, warp::Rejection> {
        storage.request_map.write().remove(&id.id);
        Ok(warp::reply::with_status(
            "Removed request from request list",
            http::StatusCode::OK,
        ))
}

async fn private_update_request_map(
    request: Request,
    storage: Storage,
    apikey: Html<&str>
    ) -> Result<impl warp::Reply, warp::Rejection> {
        if storage.request_map.read().contains_key(&request.id) == false //prevent overwriting request ids
        {
            if private_accepted_request_types().contains(&request.request_type.as_str())
            {
                let (handled, output) = handle_request(request.clone());
                if handled == true
                {
                    storage.request_map.write().insert(request.id, request.request_type);
                    Ok(warp::reply::with_status(
                        format!("{:?}",  output.unwrap()),
                        http::StatusCode::CREATED,
                    ))
                }
                else
                {
                    match output{
                        Some(ref errorstring) =>
                            Ok(warp::reply::with_status(
                                format!("Request Denied\n {:?}", output.unwrap()),
                                http::StatusCode::METHOD_NOT_ALLOWED
                            )),
                        None =>
                            Ok(warp::reply::with_status(
                                format!("Request Denied\n"),
                                http::StatusCode::METHOD_NOT_ALLOWED
                            ))
                    }
                }
            }
            else
            {
                Err(warp::reject::custom(Badrequesttype))
            }
        }
        else
        {
            Err(warp::reject::custom(Duplicateid))
        }
}

async fn public_update_request_map(
    request: Request,
    storage: Storage,
    ) -> Result<impl warp::Reply, warp::Rejection> {
        if storage.request_map.read().contains_key(&request.id) == false //prevent overwriting request ids
        {
            if public_accepted_request_types().contains(&request.request_type.as_str())
            {
                let (handled, output) = handle_request(request.clone());
                if handled == true
                {
                    storage.request_map.write().insert(request.id, request.request_type);
                    Ok(warp::reply::with_status(
                        format!("{:?}",  output.unwrap()),
                        http::StatusCode::CREATED,
                    ))
                }
                else
                {
                    match output{
                        Some(ref errorstring) =>
                            Ok(warp::reply::with_status(
                                format!("Request Denied\n {:?}", output.unwrap()),
                                http::StatusCode::METHOD_NOT_ALLOWED
                            )),
                        None =>
                            Ok(warp::reply::with_status(
                                format!("Request Denied\n"),
                                http::StatusCode::METHOD_NOT_ALLOWED
                            ))
                    }
                }
            }
            else
            {
                Err(warp::reject::custom(Badrequesttype))
            }
        }
        else
        {
            Err(warp::reject::custom(Duplicateid))
        }
}


async fn get_ordertypes() -> Result<impl warp::Reply, warp::Rejection>
{
    let filepath = "OrderTypes.json";
    if Path::new(filepath).exists()
    {
        let mut file = File::open(filepath).expect("cant open file");
        let mut contents = String::new();
        file.read_to_string(&mut contents).expect("cant read file");
        Ok(warp::reply::json(&json!(contents)))
    }
    else
    {
        Ok(warp::reply::json(&json!({"none": "none"})))
    }

}

async fn private_get_request_map(
    storage: Storage,
    apikey: Html<&str>
    ) -> Result<impl warp::Reply, warp::Rejection> {
        let result = storage.request_map.read();
        Ok(warp::reply::json(&*result))
}

fn rem_first_and_last(value: &str) -> &str {
    let mut chars = value.chars();
    chars.next();
    chars.next_back();
    chars.as_str()
}

fn handle_request(request: Request) -> (bool, Option<String>)
{
    let mut output = "";
    let mut status = false;
    if request.request_type == "publishNewOrderType"
    {
        if request.OrderTypeUUID == None
        {
            let output = &(output.to_owned() + "OrderTypeUUID variable is required!");
            return (status, Some(output.to_string()));
        }
        if request.CoinA == None
        {
            let output = &(output.to_owned() + "CoinA variable is required!");
            return (status, Some(output.to_string()));
        }
        if request.CoinB == None
        {
            let output = &(output.to_owned() + "CoinB variable is required!");
            return (status, Some(output.to_string()));
        }
        if request.CoinA_price == None
        {
            let output = &(output.to_owned() + "CoinA_price variable is required!");
            return (status, Some(output.to_string()));
        }
        if request.CoinB_price == None
        {
            let output = &(output.to_owned() + "CoinB_price variable is required!");
            return (status, Some(output.to_string()));
        }
        if request.MaxVolCoinA == None
        {
            let output = &(output.to_owned() + "MaxVolCoinA variable is required!");
            return (status, Some(output.to_string()));
        }
        else
        {
            status = true;
            let NewOrderType = json!({
                "CoinA": request.CoinA.unwrap(),
                "CoinB": request.CoinB.unwrap(),
                "CoinA_price": request.CoinA_price.unwrap(),
                "CoinB_price": request.CoinB_price.unwrap(),
                "MaxVolCoinA": request.MaxVolCoinA.unwrap()
            });
            let NewOrderTypeObj = json!({
                request.OrderTypeUUID.clone().unwrap(): NewOrderType
            });
            let mut OrderTypesObjectString = &mut NewOrderTypeObj.to_string();
            let filepath = "OrderTypes.json";
            if Path::new(filepath).exists() == false
            {
                let mut f = File::create(filepath).expect("error creating initiations.json");
                f.write_all(OrderTypesObjectString.as_bytes()).expect("error writing into OrderTypes.json");
            }
            else
            {
                let mut file = File::open(filepath).expect("cant open file");
                let mut contents = String::new();
                file.read_to_string(&mut contents).expect("cant read file");
                if contents.contains(&request.OrderTypeUUID.clone().unwrap()) == false
                {
                    let mut editedOrderTypesObjectString = rem_first_and_last(&OrderTypesObjectString).to_string();
                    let mut trimmedjson = rem_first_and_last(&contents).to_string();
                    trimmedjson.push(','); 
                    trimmedjson.push_str(&editedOrderTypesObjectString);
                    trimmedjson.insert(0, '{');
                    trimmedjson.push('}');
                    let mut f = std::fs::OpenOptions::new().write(true).truncate(true).open(filepath).expect("cant open file");
                    f.write_all(trimmedjson.as_bytes());
                    f.flush().expect("error flushing");
                }
                else
                {
                    status = false;
                    return(status, Some("Duplicate Order Type UUID".to_string()))
                }


            }
            return(status, Some("New Order Type Added".to_string()))
        }
    }
    if request.request_type == "requestEncryptedInitiation" //create an agnostic commitment for users to submit their trade offer to
    {
        if request.OrderTypeUUID == None
        {
            let output = &(output.to_owned() + "OrderTypeUUID variable is required!");
            return (status, Some(output.to_string()));
        }
        if request.ElGamalKey == None
        {
            let output = &(output.to_owned() + "ElGamalKey variable is required!");
            return (status, Some(output.to_string()));
        }
        else
        {
            status = true;
            let swapName = Uuid::new_v4().to_string();//generate a random UUID
                                                      //future impl: swapname is sha256 of the
                                                      //public initiation (ensures uniqueness)
            let filepath = "OrderTypes.json";
            let mut file = File::open(filepath).expect("cant open file");
            let mut contents = String::new();
            file.read_to_string(&mut contents).expect("cant read file");
            let OrdertypesMap: HashMap<String, Value> = serde_json::from_str(&contents).expect("Failed to parse JSON");
//            println!("{}", OrdertypesMap[&request.OrderTypeUUID.clone().unwrap()]["CoinA"]); 
            let LocalChainAccountName = accountNameFromChainAndIndex(
                rem_first_and_last(&OrdertypesMap[&request.OrderTypeUUID.clone().unwrap()]["CoinA"].to_string()).to_string(), 0);
            let CrossChainAccountName = accountNameFromChainAndIndex(
                rem_first_and_last(&OrdertypesMap[&request.OrderTypeUUID.clone().unwrap()]["CoinB"].to_string()).to_string(), 0);
            let ElGamalKey = request.ElGamalKey.unwrap();
            let ElGamalKeyPath = ElGamal_keypaths()[0];
            let InitiatorChain = OrdertypesMap[&request.OrderTypeUUID.clone().unwrap()]["CoinA"].to_string();
            let ResponderChain = OrdertypesMap[&request.OrderTypeUUID.clone().unwrap()]["CoinB"].to_string();
            
            //define order types by UUID
            //on servers end privately apply swap order information coinA / price coinB / price 
            //max volume of coin A, users can publically request this data, then when they submit a
            //initiation request they can provide the UUID of the order information they wish to
            //swap based on
            //restructure as: public call to generate an initiation specific to clients ElGamal Key
            //server responds with generic committment to specific ElGamal Key 
            //(this prevents multi-client-claiming locks)
            let command = "python3 ".to_owned()+  "-u "+ "main.py " + "GeneralizedENCInitiationSubroutine " +
                &swapName.clone() + " " + LocalChainAccountName + " " +
                CrossChainAccountName + " " + &ElGamalKey + " " + ElGamalKeyPath + " " + 
                &InitiatorChain + " " + &ResponderChain;
            //println!("{}", command);
            let mut pipe = Popen::create(&[
                "python3",  "-u", "main.py", "GeneralizedENCInitiationSubroutine",
                &swapName.clone(), LocalChainAccountName, 
                CrossChainAccountName, &ElGamalKey, ElGamalKeyPath,
                &InitiatorChain, &ResponderChain
            ], PopenConfig{
                stdout: Redirection::Pipe, ..Default::default()}).expect("err");
            let (out, err) = pipe.communicate(None).expect("err");
            if let Some(exit_status) = pipe.poll()
            {
                println!("Out: {:?}, Err: {:?}", out, err)
            }
            else
            {
                pipe.terminate().expect("err");
            }
            let mut file = File::open(swapName.clone() + "/ENC_init.bin").expect("file not found");
            let mut buf_reader = BufReader::new(file);
            let mut contents = String::new();
            buf_reader.read_to_string(&mut contents).expect("cannot read file");
            let mut outputjson =
                json!({
                    "SwapTicketID":  swapName.clone(),
                    "ENC_init.bin": contents
                });
            return (status, Some(outputjson.to_string()))
        }
        //handle a response w public request, return the finalization IF AND ONLY IF our Servers
        //pricing logic time lock security logic etc... agrees with the swap data
        //this limits the amount of RESTAPI calls we will need to make as much as possible
    }
    if request.request_type == "submitEncryptedResponse"
    {
        if request.SwapTicketID == None
        {
            let output = &(output.to_owned() + "SwapTicketID variable is required!");
            return (status, Some(output.to_string()));
        }
        if request.encryptedResponseBIN == None
        {
            let output = &(output.to_owned() + "encryptedResponseBIN variable is required!");
            return (status, Some(output.to_string()));
        }
        else
        {
            status = true;
//            println!("request.encryptedResponseBIN: {}", request.encryptedResponseBIN.clone().unwrap());
            let filepath =  format!("{}/ENC_response_path.bin", request.SwapTicketID.clone().unwrap());
            let mut f = File::create(filepath.clone()).expect("cant open file");
            f.write_all(request.encryptedResponseBIN.clone().unwrap().as_bytes()).expect("cant open file");
            f.flush().expect("error flushing");
            drop(f);
            let filepath = request.SwapTicketID.clone().unwrap() + "/initiator.json";
            let mut file = File::open(filepath).expect("cant open file");
            let mut contents = String::new();
            file.read_to_string(&mut contents).expect("cant read file");
            let SwapMap: HashMap<String, Value> = serde_json::from_str(&contents).expect("Failed to parse JSON");
            let initiatorJSONPath = rem_first_and_last(&SwapMap["initiatorJSONPath"].to_string()).to_string();
            let mut pipe = Popen::create(&[
                "python3",  "-u", "main.py", "GeneralizedENC_FinalizationSubroutine", &initiatorJSONPath
            ], PopenConfig{
                stdout: Redirection::Pipe, ..Default::default()}).expect("err");
            let (out, err) = pipe.communicate(None).expect("err");
            if let Some(exit_status) = pipe.poll()
            {
                println!("Out: {:?}, Err: {:?}", out, err)
            }
            else
            {
                pipe.terminate().expect("err");
            }        
            let filepath = request.SwapTicketID.clone().unwrap() + "/ENC_finalization.bin";
            let mut file = File::open(filepath).expect("cant open file");
            let mut contents = String::new();
            file.read_to_string(&mut contents).expect("cant read file");
            let child_thread = thread::spawn(move|| {
                let mut child_process = 
                    Command::new("python3")
                    .arg("-u")
                    .arg("main.py")
                    .arg("GeneralizedENC_InitiatorClaimSubroutine")
                    .arg(initiatorJSONPath)
                    .stdout(Stdio::piped()) // Redirect stdout to /dev/null or NUL to detach from parent
                    .stderr(Stdio::null()) // Redirect stderr to /dev/null or NUL to detach from parent
                    .spawn()
                    .expect("Failed to start subprocess");

                let mut output = String::new();
                let mut error_output = String::new();
                child_process.stdout.unwrap().read_to_string(&mut output).expect("Failed to read stdout");

                // Capture and read stderr
                child_process.stderr.unwrap().read_to_string(&mut error_output).expect("Failed to read stderr");

                let exit_status = child_process.wait().expect("Failed to wait for subprocess");
                if !exit_status.success() {
                    eprintln!("Subprocess failed with exit code: {:?}", exit_status);
                }
                eprintln!("Subprocess failed with exit code: {:?}", exit_status);
                eprintln!("Subprocess error output:\n{}", error_output);
            });
            return (status, Some(contents.to_string()))
        }
    }
    //instead of private finalize swap endpoint first accept public postresponse endpoint that
    //checks the value of the coins in the response contract and finalizes based on a pricing
    //algorithm, private calls after generateSwapInitiator would likely only be used in recovery
    //scenarios. this leverages automating checking for swap finalization or refunding on the
    //clients side and automating the initiators check that the responder has claimed so he can
    //claim or else he can refund
    /*
    if request.request_type == "finalizeSwap" //finalize a specific swap 
    {
        if request.InitiatorJSONPath == None
        {
            let output = &(output.to_owned() + "InitiatorJSONPath variable is required!");
            return (status, Some(output.to_string()));
        }
        else
        {
            let status = true;
            /call Atomic API here
            return (status, None)
        }
    }
    if request.request_type == "claimSwapFunds" //claim funds from a finalized and accepted completed swap
    {
        if request.InitiatorJSONPath == None
        {
            let output = &(output.to_owned() + "InitiatorJSONPath variable is required!");
            return (status, Some(output.to_string()));
        }
        else
        {
            let status = true;
            //call Atomic API here
            return (status, None)
        }
    }
    if request.request_type == "refundSwap" //refund the coins from an unclaimed or unfinalized swap
    {
        if request.InitiatorJSONPath == None
        {
            let output = &(output.to_owned() + "InitiatorJSONPath variable is required!");
            return (status, Some(output.to_string()));
        }
        else
        {
            let status = true;
            //call Atomic API here
            return (status, None)
        }
    }*/
    else
    {
        return  (status, Some("Unknown Error".to_string()));
    }
}

type RequestMap = HashMap<String, String>;

#[derive(Debug)]
struct Badapikey;
impl warp::reject::Reject for Badapikey {}

#[derive(Debug)]
struct Noapikey;
impl warp::reject::Reject for Noapikey {}

#[derive(Debug)]
struct Duplicateid;
impl warp::reject::Reject for Duplicateid {}

#[derive(Debug)]
struct Badrequesttype;
impl warp::reject::Reject for Badrequesttype {}


#[derive(Debug, Deserialize, Serialize, Clone)]
struct Id {
    id: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct Request {
    id: String,
    request_type: String,
    swapName: Option<String>,
    LocalChainAccountName: Option<String>,
    CrossChainAccountName: Option<String>,
    ElGamalKey:  Option<String>,
    ElGamalKeyPath: Option<String>,
    InitiatorChain: Option<String>,
    ResponderChain: Option<String>,
    InitiatorJSONPath: Option<String>,
    OrderTypeUUID: Option<String>,
    CoinA: Option<String>,
    CoinB: Option<String>,
    CoinA_price: Option<String>,
    CoinB_price: Option<String>,
    MaxVolCoinA: Option<String>,
    SwapTicketID: Option<String>,
    encryptedResponseBIN: Option<String>
    //ResponderJSONPath not ready yet
}

#[derive(Clone)]
struct Storage {
   request_map: Arc<RwLock<RequestMap>>
}

impl Storage {
    fn new() -> Self {
        Storage {
            request_map: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

