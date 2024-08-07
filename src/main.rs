use pyo3::types::PyDict;
use pyo3::types::PyList;
use std::path::Path;
use tokio::{task};
use tokio::task::spawn_blocking;
use tokio::io::AsyncReadExt;
use futures::{Future, future};
use warp::Filter;
use warp::http::Response;
use warp::hyper::header::HeaderValue;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use warp::hyper;
use warp::reply;
use warp::filters::cors::cors;
use std::process::{Command, Stdio};
use std::thread;
use uuid::{uuid, Uuid};
use std::fs::OpenOptions;
use serde_json::{json, Value, Map};
use warp::{http, http::Method};
use std::io::BufReader;
use std::fs::File;
use std::fs;
use std::io::prelude::*;
use warp::reply::Html;
use warp::Reply;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use regex::Regex;
use serde::{Deserialize, Serialize};
use subprocess::{PopenConfig, Popen, Redirection};
mod json_fns;
use json_fns::{json_body, delete_json};
mod API_keys;
use API_keys::{accepted_public_api_keys, accepted_private_api_keys};
mod accepted_request_types;
use accepted_request_types::{private_accepted_request_types, public_accepted_request_types};
mod get_fns;
use get_fns::{get_starterAPIKeys, get_ElGamalPubs, get_ElGamalQGChannels, get_QGPubkeyArray, get_ordertypes, private_get_request_map};
mod json_tools;
use json_tools::{readJSONfromfilepath};
mod delete_fns;
use delete_fns::{private_delete_request};
mod update_fns;
use update_fns::{public_update_request_map, private_update_request_map};
mod str_tools;
use str_tools::{rem_first_and_last};
mod swap_tools;
use swap_tools::{set_swap_state, update_local_swap_state_map, load_local_swap_state_map, check_swap_state_map_against_swap_dirs, restore_state};
use std::os::unix::process::CommandExt;
use nix::libc;
use pyo3::prelude::*;
use pyo3::types::PyTuple;
fn insert_into_nested_map(
    outer_map: &mut SingleNestMap,
    outer_key: &str,
    inner_key: &str,
    inner_value: &str,
) ->  SingleNestMap
{
    outer_map
        .entry(outer_key.to_string())
        .or_insert_with(HashMap::new)
        .insert(inner_key.to_string(), inner_value.to_string());
    return outer_map.clone()
}




fn is_directory(path: &str) -> bool {
    match fs::metadata(path) {
        Ok(metadata) => metadata.is_dir(),
        Err(_) => false,
    }
}

fn is_file(path: &str) -> bool {
    match fs::metadata(path) {
        Ok(metadata) => metadata.is_file(),
        Err(_) => false,
    }
}


fn check_if_uuid_fmt(input: &str) -> bool
{
    let regex = Regex::new(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}").unwrap();
    if regex.is_match(input) == true
    {
        return true //is formatted like uuid
    }
    else
    {
        return false //is not formatted like uuid
    }
}


fn checkAccountLoggedInStatus(encEnvPath: &str, storage: Storage) -> bool
{
    let s = storage.loggedInAccountMap.read().clone();
    return s.contains_key(encEnvPath)
}

fn get_testnet_ergo_accounts() -> Vec<String>
{
    let testnetErgoFrameworkPathStr = "Ergo/SigmaParticle/";
    let testnetErgoFrameworkPath = Path::new(testnetErgoFrameworkPathStr);
    let expected_dirs = vec![
            "AtomicMultiSig", "AtomicMultiSigECC", "basic_framework", "boxFilter", "boxValue",
            "cpp", "getTreeFromBox", "treeToAddr", "boxConstantByIndex",
            "boxToContract", "currentHeight", "currentHeight", "valFromHex", "testaccountname", "SwapKeyManager"
    ];
    let mut accounts = vec![];
    if testnetErgoFrameworkPath.is_dir() {
        for entry in fs::read_dir(testnetErgoFrameworkPath).expect("failed to read dir entry") {
            let entry = entry.expect("error getting entry");
            let path = entry.path();
            if path.is_dir()
            {
                let path_str = path.to_str().unwrap_or("").to_string();
                let pathref = &path.to_str();
                if let Some(dir_name) = path.file_name().and_then(|name| name.to_str()) {
                    if !expected_dirs.contains(&dir_name) {
                        if Uuid::parse_str(&path_str).is_err() {
                            if check_if_uuid_fmt(&path_str) == false
                            {
                                let accountName = path_str.clone().replace(testnetErgoFrameworkPathStr, "");
                                accounts.push(accountName.clone());
                                dbg!(&accountName);
                            }
                        }
                    }
                }
            }
        }
    }
    return accounts
    //go through the framework dir
    //find any outlier dir that isnt a uuid swap dir
}

fn get_sepolia_accounts() -> Vec<String>
{
    let Sepolia_framework_path_str = "EVM/Atomicity/";
    let Sepolia_framework_path = Path::new(Sepolia_framework_path_str);
    let expected_dirs = vec![
        "AtomicMultiSigSecp256k1", "AtomicMultiSigSecp256k1_0.0.1", "basic_framework",
        "cpp", "Goerli", "Sepolia", "solidity-flattener", "testaccountname"
    ];
    let mut accounts = vec![];
    for entry in fs::read_dir(Sepolia_framework_path).expect("failed to read dir entry")
    {
        let entry = entry.expect("error getting entry");
        let path = entry.path();
        if path.is_dir()
        {
            let path_str = path.to_str().unwrap_or("").to_string();
            let pathref = &path.to_str();
            if let Some(dir_name) = path.file_name().and_then(|name| name.to_str()) {
                if !expected_dirs.contains(&dir_name) {
                    if !dir_name.starts_with("Swap_") {
                        let accountName = path_str.clone().replace(Sepolia_framework_path_str, "");
                        accounts.push(accountName.clone());
                        dbg!(&accountName);
                    }
                }
            }
        }
    }
    return accounts
}

fn accountNameFromChainAndIndex(chain: &str, index: usize) -> String {
    let TestnetErgo: String = "TestnetErgo".to_string();
    let Sepolia: String = "Sepolia".to_string();
    match chain {
        "TestnetErgo" => {
            dbg!("ergo");
            return get_testnet_ergo_accounts()[index].clone();
        }
        "Sepolia" => {
            dbg!("sepolia");
            return get_sepolia_accounts()[index].clone();
        }
        _ => "chain not found".to_string(),
    }
}

fn market_pricing_loop()
{
    tokio::spawn(async move {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let code = std::fs::read_to_string("market_pricing.py").unwrap();
            pyo3::prepare_freethreaded_python();
            let activators = PyModule::from_code_bound(py, &code, "market_pricing", "market_pricing").unwrap();
            activators.getattr("marketPricingLoop").unwrap()
            .call0(
            ).unwrap();
        });
    });
}

#[tokio::main]
async fn main() {
    let version =  "v0.0.1";
    let main_path  = "requests";
    let public_main_path = "publicrequests";
    let OrderTypesPath = "ordertypes";
    let ElGamalPubsPath = "ElGamalPubs";
    let ElGamalQGChannelsPath = "ElGamalQGChannels";
    let QGPubkeyArrayPath = "QGPubkeyArray";
    let GetStarterAPIKeysPath = "starterAPIKeys";
    let cors = cors()
        .allow_any_origin()
        .allow_methods(vec!["GET", "POST"])
        .allow_headers(vec!["Content-Type", "Authorization"]);
    let mut storage = Storage::new();
    let sc = storage.clone();
    let storage_filter = warp::any().map(move || sc.clone());
    let bearer_public_api_key_filter = warp::header::<String>("Authorization").and_then( | auth_header: String | async move {
            if auth_header.starts_with("Bearer ")
            {
                let api_key = auth_header.trim_start_matches("Bearer ").to_string();
                if accepted_public_api_keys().contains(&api_key)
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
    let bearer_private_api_key_filter = warp::header::<String>("Authorization").and_then( | auth_header: String | async move {
            if auth_header.starts_with("Bearer ")
            {
                let api_key = auth_header.trim_start_matches("Bearer ").to_string();
                if accepted_private_api_keys().contains(&api_key)
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
    market_pricing_loop();
    let mut loaded_swap_state_map = check_swap_state_map_against_swap_dirs(load_local_swap_state_map());
    storage.update_swap_state_map(loaded_swap_state_map.clone());
    update_local_swap_state_map(loaded_swap_state_map);
    restore_state(storage.clone()).await;
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
        .and_then(get_ordertypes)
        .with(cors.clone());
    let public_add_requests = warp::post()
        .and(warp::path(version))
        .and(warp::path(public_main_path))
        .and(warp::path::end())
        .and(json_body())
        .and(storage_filter.clone())
        .and(bearer_public_api_key_filter)
        .and_then(public_update_request_map)
        .with(cors.clone());
    let get_ElGamalPubs = warp::get()
        .and(warp::path(version))
        .and(warp::path(public_main_path))
        .and(warp::path(ElGamalPubsPath))
        .and(warp::path::end())
        .and_then(get_ElGamalPubs)
        .with(cors.clone());
    let get_ElGamalQGChannels = warp::get()
        .and(warp::path(version))
        .and(warp::path(public_main_path))
        .and(warp::path(ElGamalQGChannelsPath))
        .and(warp::path::end())
        .and_then(get_ElGamalQGChannels)
        .with(cors.clone());
    let get_QGPubkeyArray = warp::get()
        .and(warp::path(version))
        .and(warp::path(public_main_path))
        .and(warp::path(QGPubkeyArrayPath))
        .and(warp::path::end())
        .and_then(get_QGPubkeyArray)
        .with(cors.clone());
    let get_starterAPIKeys = warp::get()
        .and(warp::path(version))
        .and(warp::path(public_main_path))
        .and(warp::path(GetStarterAPIKeysPath))
        .and(warp::path::end())
        .and_then(get_starterAPIKeys)
        .with(cors.clone());
    let routes = 
        add_requests.or(get_requests).or(update_request).or(private_delete_request)
        .or(public_ordertypes_get_request).or(public_add_requests)
        .or(get_ElGamalPubs).or(get_ElGamalQGChannels).or(get_QGPubkeyArray).or(get_starterAPIKeys);
    warp::serve(routes)
        .run(([127, 0, 0, 1], 3030)).await;
    
}


async fn handle_request(request: Request, storage: Storage) -> (bool, Option<String>)
{
    return tokio::spawn(async move { 
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
        if request.MinVolCoinA == None
        {
            let output = &(output.to_owned() + "MinVolCoinA variable is required!");
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
                "MaxVolCoinA": request.MaxVolCoinA.unwrap(),
                "MinVolCoinA": request.MinVolCoinA.unwrap()
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
        if request.QGChannel == None
        {
            let output = &(output.to_owned() + "QGChannel variable is required!");
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
//            dbg!(&swapName);
//
//
            let mut swapDataMap: HashMap<String, String> = HashMap::new();
            swapDataMap.insert("SwapRole".to_string(), "Initiator".to_string());
            swapDataMap.insert("OrderTypeUUID".to_string(), request.OrderTypeUUID.clone().unwrap().replace("\\", "").replace("\"", ""));
            swapDataMap.insert("QGChannel".to_string(), request.QGChannel.clone().unwrap().replace("\\", "").replace("\"", ""));
            let clientElGamalKey = request.ElGamalKey.clone().unwrap_or_default().replace("\\", "").replace("\"", "");
            swapDataMap.insert("ClientElGamalKey".to_string(), remove_quotes(&clientElGamalKey));


            let QGPubkeyArrayFilepath = "QGPubkeyArray.json";
            let mut  QGPubkeyArrayFile = File::open(QGPubkeyArrayFilepath).expect("cant open file");
            let mut QGPubkeyArray =  String::new();
            QGPubkeyArrayFile.read_to_string(&mut QGPubkeyArray).expect("cant read file");
            let QGPubkeyArrayMap : HashMap<String, Value> = serde_json::from_str(&QGPubkeyArray).expect("Failed to parse JSON");
            let QGCandidate = request.QGChannel.clone().unwrap();
            let mut CompatPubkey = String::new();
            let mut ElGKeyIndex = String::new();
            if let Some((key, _)) = QGPubkeyArrayMap.iter().find(|(_, &ref v)| *v == *&QGPubkeyArrayMap[&QGCandidate])
            {
                CompatPubkey = (&QGPubkeyArrayMap[&QGCandidate]).to_string();
                let compatpubkeystr = &QGPubkeyArrayMap[&QGCandidate];
                println!("match: qg: {}, pubkey: {}", key, CompatPubkey);
                //if we get here we have a compatible pubkey and Q already
                //load key index map
                let ElGKeyIndexMapFilePath = "ElGamalPubKeys.json";
                let mut ElGKeyIndexMapFile = File::open(ElGKeyIndexMapFilePath).expect("cant open file");
                let mut ElGKeyIndexMapString = String::new();
                ElGKeyIndexMapFile.read_to_string(&mut ElGKeyIndexMapString).expect("cant read file");
                let ElGKeyIndexMap : HashMap<String, Value> = serde_json::from_str(&ElGKeyIndexMapString).expect("Failed to parse JSON");
                if  let Some((key, _)) = ElGKeyIndexMap.iter().find(|(_, &ref v)| v == compatpubkeystr)
                {
                   ElGKeyIndex = key.to_string();
                }
                else
                {
                    //need to run index update here??
                }
            }
            else
            {
                //TODO handle novel Q Channel values given by clients
                println!("Unhandled: New Q Value Suggested by Client");
            }
            //MAJOR TODO TODO:!!!!make sure to save chosen pubkey and channel into swap folder!!!TODO TODO
            swapDataMap.insert("ElGamalKey".to_string(), CompatPubkey.clone().replace("\\", "").replace("\"", ""));
            let ElGamalKeyPath = "Key".to_owned() + &ElGKeyIndex + ".ElGamalKey"; 
            swapDataMap.insert("ElGamalKeyPath".to_string(), remove_quotes(&ElGamalKeyPath.clone()));


            let filepath = "OrderTypes.json";
            let mut file = File::open(filepath).expect("cant open file");
            let mut contents = String::new();
            file.read_to_string(&mut contents).expect("cant read file");
            let OrdertypesMap: HashMap<String, Value> = serde_json::from_str(&contents).expect("Failed to parse JSON");
//            println!("{}", OrdertypesMap[&request.OrderTypeUUID.clone().unwrap()]["CoinA"]); 
            let LocalChainAccountName = accountNameFromChainAndIndex(
                rem_first_and_last(&OrdertypesMap[&request.OrderTypeUUID.clone().unwrap()]["CoinA"].to_string()), 0);
            //TODO MODULAR ACCOUNT INDEXING
            let CrossChainAccountName = accountNameFromChainAndIndex(
                rem_first_and_last(&OrdertypesMap[&request.OrderTypeUUID.clone().unwrap()]["CoinB"].to_string()), 0);
            dbg!(&OrdertypesMap[&request.OrderTypeUUID.clone().unwrap()]["CoinB"].to_string());
            dbg!(&CrossChainAccountName);
            let ElGamalKey = request.ElGamalKey.unwrap(); //key sent by client 
            let InitiatorChain = OrdertypesMap[&request.OrderTypeUUID.clone().unwrap()]["CoinA"].to_string().replace("\"", "");
            let ResponderChain = OrdertypesMap[&request.OrderTypeUUID.clone().unwrap()]["CoinB"].to_string().replace("\"", "");
            
            swapDataMap.insert(
                "LocalChainAccount".to_string(),
                LocalChainAccountName.to_string().clone()
            );
            swapDataMap.insert(
                "CrossChainAccount".to_string(),
                CrossChainAccountName.to_string().clone()
            );
            swapDataMap.insert("LocalChain".to_string(), InitiatorChain.clone());
            swapDataMap.insert("CrossChain".to_string(), ResponderChain.clone());
            swapDataMap.insert("SwapState".to_string(), "initiating".to_string());
            storage.swapStateMap.write().insert(swapName.clone().to_string(), swapDataMap.clone());
//            let swapStateMapString = format!("{:#?}", &*storage.swapStateMap.read());
            let swapStateMapString = serde_json::to_string_pretty(&*storage.swapStateMap.read()).unwrap();
            fs::write("SwapStateMap", swapStateMapString).expect("Unable to write file");
            //define order types by UUID
            //on servers end privately apply swap order information coinA / price coinB / price 
            //max volume of coin A, users can publically request this data, then when they submit a
            //initiation request they can provide the UUID of the order information they wish to
            //swap based on
            //restructure as: public call to generate an initiation specific to clients ElGamal Key
            //server responds with generic committment to specific ElGamal Key 
            //(this prevents multi-client-claiming locks)
            //
            //check for encrypted account paths
            //if they exist check for those accounts to be logged in
            //if they are not prompt server to log them in
            //if they are proceed with a different command that includes their passwords as last 2
            //args
            fn checkAccountLoggedInStatus(encEnvPath: &str, storage: Storage) -> bool
            {
                let s = storage.loggedInAccountMap.read().clone();
                return s.contains_key(encEnvPath)  
            }
            let mut localChainAccountPassword = String::new();
            let mut crossChainAccountPassword = String::new();
            dbg!(&InitiatorChain);
            dbg!(&ResponderChain);
            if InitiatorChain == "TestnetErgo"
            {
                let chainFrameworkPath = "Ergo/SigmaParticle/";
                let encEnvPath = chainFrameworkPath.to_owned() + &LocalChainAccountName + "/.env.encrypted";
                dbg!(&encEnvPath);
                let exists = if let Ok(_) = fs::metadata(encEnvPath.clone()) {
                    true
                } else {
                    false
                };
                if exists
                {
                    if checkAccountLoggedInStatus(&encEnvPath, storage.clone()) == true
                    {
                        localChainAccountPassword = storage.loggedInAccountMap.read()[&encEnvPath].clone();
                    }
                    else
                    {
                        let errstr = InitiatorChain.to_owned() + " " +  &LocalChainAccountName + " is not logged in!";
                        dbg!(&errstr);
                        return (false, Some(errstr.to_string()))
                    }
                }
            }
            if ResponderChain == "Sepolia"
            {
                let chainFrameworkPath = "EVM/Atomicity/";
                let encEnvPath = chainFrameworkPath.to_owned() + &CrossChainAccountName + "/.env.encrypted";
                dbg!(&encEnvPath);
                let exists = if let Ok(_) = fs::metadata(encEnvPath.clone()) {
                    true
                } else {
                    false
                };
                if exists
                {
                    if checkAccountLoggedInStatus(&encEnvPath, storage.clone()) == true
                    {
                        crossChainAccountPassword = storage.loggedInAccountMap.read()[&encEnvPath].clone();
                    }
                    else
                    {
                        let errstr = ResponderChain.to_owned() + " " + &CrossChainAccountName + " is not logged in!";
                        dbg!(&errstr);
                        return (false, Some(errstr.to_string()))
                    }
                }
            }
            if localChainAccountPassword == String::new() && crossChainAccountPassword == String::new()
            {
/*                let command = "python3 ".to_owned()+  "-u "+ "main.py " + "GeneralizedENCInitiationSubroutine " +
                    &swapName.clone() + " " + &LocalChainAccountName + " " +
                    &CrossChainAccountName + " " + &ElGamalKey + " " + &ElGamalKeyPath + " " + 
                    &InitiatorChain + " " + &ResponderChain;
                //println!("{}", command);
                dbg!("python3",  "-u", "main.py", "GeneralizedENCInitiationSubroutine",
                    &swapName.clone(), &LocalChainAccountName,
                    &CrossChainAccountName, &ElGamalKey, &ElGamalKeyPath,
                    &InitiatorChain, &ResponderChain);*/
                let mut pipe = Popen::create(&[
                    "python3",  "-u", "main.py", "GeneralizedENCInitiationSubroutine",
                    &swapName.clone(), &LocalChainAccountName, 
                    &CrossChainAccountName, &ElGamalKey, &ElGamalKeyPath,
                    &InitiatorChain, &ResponderChain
                ], PopenConfig{
                    //detached: true,
                    stdout: Redirection::Pipe,
                    ..Default::default()
                }).expect("err");
                let (out, err) = pipe.communicate(None).expect("err");
                if let Some(exit_status) = pipe.poll()
                {
                    println!("Out: {:?}, Err: {:?}", out, err)
                }
                else
                {
                    pipe.terminate().expect("err");
                }
                let OrderTypeUUID = request.OrderTypeUUID.clone().unwrap();
                let mut file = File::open(swapName.clone() + "/ENC_init.bin").expect("file not found");
                let mut buf_reader = BufReader::new(file);
                let mut buffer = String::new();
                buf_reader.read_to_string(&mut buffer).expect("cannot read file");
                let mut filepath = swapName.clone() + "/OrderTypeUUID";
                let mut f = std::fs::OpenOptions::new().create_new(true).write(true).truncate(true).open(filepath).expect("cant open file");
                f.write_all(&OrderTypeUUID.clone().as_bytes());
                f.flush().expect("error flushing");
                let mut outputjson =
                    json!({
                        "SwapTicketID":  swapName.clone(),
                        "ENC_init.bin": buffer
                    });
                set_swap_state(&swapName.clone(), "initiated_submitted");
                return (status, Some(outputjson.to_string()))
            }
            if localChainAccountPassword != String::new() && crossChainAccountPassword == String::new()
            {
                let mut pipe = Popen::create(&[
                    "python3",  "-u", "main.py", "GeneralizedENCInitiationSubroutine_localENCOnly",
                    &swapName.clone(), &LocalChainAccountName,
                    &CrossChainAccountName, &ElGamalKey, &ElGamalKeyPath,
                    &InitiatorChain, &ResponderChain,
                    &localChainAccountPassword
                ], PopenConfig{
                    //detached: true,
                    stdout: Redirection::Pipe,
                    ..Default::default()
                }).expect("err");
                let (out, err) = pipe.communicate(None).expect("err");
                if let Some(exit_status) = pipe.poll()
                {
                    println!("Out: {:?}, Err: {:?}", out, err)
                }
                else
                {
                    pipe.terminate().expect("err");
                }
                let OrderTypeUUID = request.OrderTypeUUID.clone().unwrap();
                let mut file = File::open(swapName.clone() + "/ENC_init.bin").expect("file not found");
                let mut buf_reader = BufReader::new(file);
                let mut buffer = String::new();
                buf_reader.read_to_string(&mut buffer).expect("cannot read file");
                let mut filepath = swapName.clone() + "/OrderTypeUUID";
                let mut f = std::fs::OpenOptions::new().create_new(true).write(true).truncate(true).open(filepath).expect("cant open file");
                f.write_all(&OrderTypeUUID.clone().as_bytes());
                f.flush().expect("error flushing");
                let mut outputjson =
                    json!({
                        "SwapTicketID":  swapName.clone(),
                        "ENC_init.bin": buffer
                    });
                set_swap_state(&swapName.clone(), "initiated_submitted");
                return (status, Some(outputjson.to_string()))
            }
            if localChainAccountPassword == String::new() && crossChainAccountPassword != String::new()
            {
                let mut pipe = Popen::create(&[
                    "python3",  "-u", "main.py", "GeneralizedENCInitiationSubroutine_crossENCOnly",
                    &swapName.clone(), &LocalChainAccountName,
                    &CrossChainAccountName, &ElGamalKey, &ElGamalKeyPath,
                    &InitiatorChain, &ResponderChain,
                    &crossChainAccountPassword
                ], PopenConfig{
                    //detached: true,
                    stdout: Redirection::Pipe,
                    ..Default::default()
                }).expect("err");
                let (out, err) = pipe.communicate(None).expect("err");
                if let Some(exit_status) = pipe.poll()
                {
                    println!("Out: {:?}, Err: {:?}", out, err)
                }
                else
                {
                    pipe.terminate().expect("err");
                }
                let OrderTypeUUID = request.OrderTypeUUID.clone().unwrap();
                let mut file = File::open(swapName.clone() + "/ENC_init.bin").expect("file not found");
                let mut buf_reader = BufReader::new(file);
                let mut buffer = String::new();
                buf_reader.read_to_string(&mut buffer).expect("cannot read file");
                let mut filepath = swapName.clone() + "/OrderTypeUUID";
                let mut f = std::fs::OpenOptions::new().create_new(true).write(true).truncate(true).open(filepath).expect("cant open file");
                f.write_all(&OrderTypeUUID.clone().as_bytes());
                f.flush().expect("error flushing");
                let mut outputjson =
                    json!({
                        "SwapTicketID":  swapName.clone(),
                        "ENC_init.bin": buffer
                    });
                set_swap_state(&swapName.clone(), "initiated_submitted");
                return (status, Some(outputjson.to_string()))
            }
            else 
            {
                let mut pipe = Popen::create(&[
                    "python3",  "-u", "main.py", "GeneralizedENCInitiationSubroutine",
                    &swapName.clone(), &LocalChainAccountName,
                    &CrossChainAccountName, &ElGamalKey, &ElGamalKeyPath,
                    &InitiatorChain, &ResponderChain,
                    &localChainAccountPassword, &crossChainAccountPassword
                ], PopenConfig{
                    //detached: true,
                    stdout: Redirection::Pipe,
                    ..Default::default()
                }).expect("err");
                let (out, err) = pipe.communicate(None).expect("err");
                if let Some(exit_status) = pipe.poll()
                {
                    println!("Out: {:?}, Err: {:?}", out, err)
                }
                else
                {
                    pipe.terminate().expect("err");
                }
                let OrderTypeUUID = request.OrderTypeUUID.clone().unwrap();
                let mut file = File::open(swapName.clone() + "/ENC_init.bin").expect("file not found");
                let mut buf_reader = BufReader::new(file);
                let mut buffer = String::new();
                buf_reader.read_to_string(&mut buffer).expect("cannot read file");
                let mut filepath = swapName.clone() + "/OrderTypeUUID";
                let mut f = std::fs::OpenOptions::new().create_new(true).write(true).truncate(true).open(filepath).expect("cant open file");
                f.write_all(&OrderTypeUUID.clone().as_bytes());
                f.flush().expect("error flushing");
                let mut outputjson =
                    json!({
                        "SwapTicketID":  swapName.clone(),
                        "ENC_init.bin": buffer
                    });
                set_swap_state(&swapName.clone(), "initiated_submitted");
                return (status, Some(outputjson.to_string()))
            }
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
            let mut filepath = request.SwapTicketID.clone().unwrap() + "/OrderTypeUUID";
            let mut file = File::open(filepath).expect("cant open file");
            let mut OrderTypeUUID = String::new();
            file.read_to_string(&mut OrderTypeUUID).expect("cant read file");

            let mut filepath = "OrderTypes.json";
            let mut file = File::open(filepath).expect("cant open file");
            let mut OrderTypes = String::new();
            file.read_to_string(&mut OrderTypes).expect("cant read file");
            let OrderTypeMap: HashMap<String, Value> = serde_json::from_str::<HashMap<String, Value>>(&OrderTypes).expect("Failed to parse JSON").clone();
            let CoinA_Price = serde_json::from_str::<HashMap<String, Value>>(&OrderTypes).expect("Failed to parse JSON")[&OrderTypeUUID]["CoinA_price"].clone();
            let CoinB_Price = serde_json::from_str::<HashMap<String, Value>>(&OrderTypes).expect("Failed to parse JSON")[&OrderTypeUUID]["CoinB_price"].clone();
            dbg!(CoinA_Price, CoinB_Price);
            fn checkAccountLoggedInStatus(encEnvPath: &str, storage: Storage) -> bool
            {
                let s = storage.loggedInAccountMap.read().clone();
                return s.contains_key(encEnvPath)
            }

            let InitiatorChain = serde_json::from_str::<HashMap<String, Value>>(&OrderTypes).expect("Failed to parse JSON")[&OrderTypeUUID.clone()]["CoinA"].clone().to_string().replace("\"", "").clone();
            let ResponderChain = serde_json::from_str::<HashMap<String, Value>>(&OrderTypes).expect("Failed to parse JSON")[&OrderTypeUUID.clone()]["CoinB"].clone().to_string().replace("\"", "").clone();
            let LocalChainAccountName = accountNameFromChainAndIndex(
                rem_first_and_last(&OrderTypeMap[&OrderTypeUUID.clone()]["CoinA"].to_string()), 0);
            let CrossChainAccountName = accountNameFromChainAndIndex(
                rem_first_and_last(&OrderTypeMap[&OrderTypeUUID.clone()]["CoinB"].to_string()), 0);


            let mut localChainAccountPassword = String::new();
            let mut crossChainAccountPassword = String::new();
            dbg!(&InitiatorChain);
            dbg!(&ResponderChain);
            if InitiatorChain == "TestnetErgo"
            {
                let chainFrameworkPath = "Ergo/SigmaParticle/";
                let encEnvPath = chainFrameworkPath.to_owned() + &LocalChainAccountName + "/.env.encrypted";
                dbg!(&encEnvPath);
                let exists = if let Ok(_) = fs::metadata(encEnvPath.clone()) {
                    true
                } else {
                    false
                };
                if exists
                {
                    if checkAccountLoggedInStatus(&encEnvPath, storage.clone()) == true
                    {
                        localChainAccountPassword = storage.loggedInAccountMap.read()[&encEnvPath].clone();
                    }
                    else
                    {
                        let errstr = InitiatorChain.to_owned() + " " +  &LocalChainAccountName + " is not logged in!";
                        dbg!(&errstr);
                        return (false, Some(errstr.to_string()))
                    }
                }
            }
            if ResponderChain == "Sepolia"
            {
                let chainFrameworkPath = "EVM/Atomicity/";
                let encEnvPath = chainFrameworkPath.to_owned() + &CrossChainAccountName + "/.env.encrypted";
                dbg!(&encEnvPath);
                let exists = if let Ok(_) = fs::metadata(encEnvPath.clone()) {
                    true
                } else {
                    false
                };
                if exists
                {
                    if checkAccountLoggedInStatus(&encEnvPath, storage.clone()) == true
                    {
                        crossChainAccountPassword = storage.loggedInAccountMap.read()[&encEnvPath].clone();
                    }
                    else
                    {
                        let errstr = ResponderChain.to_owned() + " " + &CrossChainAccountName + " is not logged in!";
                        dbg!(&errstr);
                        return (false, Some(errstr.to_string()))
                    }
                }
            }
            let CoinA_Price = serde_json::from_str::<HashMap<String, Value>>(&OrderTypes).expect("Failed to parse JSON")[&OrderTypeUUID]["CoinA_price"].clone();
            let CoinB_Price = serde_json::from_str::<HashMap<String, Value>>(&OrderTypes).expect("Failed to parse JSON")[&OrderTypeUUID]["CoinB_price"].clone(); 
            if localChainAccountPassword == String::new() && crossChainAccountPassword == String::new()
            {
                pyo3::prepare_freethreaded_python();
                Python::with_gil(|py| {
                    let code = std::fs::read_to_string("initiatorInterface.py").unwrap();
                    pyo3::prepare_freethreaded_python();
                    let activators = PyModule::from_code_bound(py, &code, "initiatorInterface.py", "initatorInterface").unwrap();
                    let args = PyTuple::new_bound(py, &[
                        &initiatorJSONPath,
                        &CoinA_Price.to_string(),
                        &CoinB_Price.to_string()
                    ]);
                    match activators.getattr("GeneralizedENC_FinalizationSubroutine").unwrap().call1( &args) {
                            Ok(out) => {
                                // Handle the successful output
                                //let extract: String
                                    //= out.extract().expect("error getting traceback to string");
                                dbg!(out,); //extract);
                            }
                            Err(err) => {
                                // Handle the exception and print the traceback
                                let traceback_module = PyModule::import_bound(py, "traceback").unwrap();
                                let traceback_obj = traceback_module.getattr("format_exception").unwrap();
                                let exc_tb = err.traceback_bound(py);
                                println!("{}{}", exc_tb.unwrap().format().unwrap(), err);

                            }
                        }
                });
                tokio::spawn(async move {
                    pyo3::prepare_freethreaded_python();
                    Python::with_gil(|py| {
                        let code = std::fs::read_to_string("initiatorInterface.py").unwrap();
                        pyo3::prepare_freethreaded_python();
                        let activators = PyModule::from_code_bound(py, &code, "initiatorInterface.py", "initatorInterface").unwrap();
                        let args = PyTuple::new_bound(py, &[
                            &initiatorJSONPath,
                        ]);
                        match activators.getattr("GeneralizedENC_InitiatorClaimSubroutine").unwrap().call1( &args) {
                            Ok(out) => {
                                // Handle the successful output
/*                                //let extract: String
                                    //= out.extract().expect("error getting traceback to string");*/
                                dbg!(out,); //extract);
                            }
                            Err(err) => {
                                // Handle the exception and print the traceback
                                let traceback_module = PyModule::import_bound(py, "traceback").unwrap();
                                let traceback_obj = traceback_module.getattr("format_exception").unwrap();
                                let exc_tb = err.traceback_bound(py);
                                println!("{}{}", exc_tb.unwrap().format().unwrap(), err.to_string());
                                
                            }
                        }

                    });
                });
            }
            else if localChainAccountPassword == String::new() && crossChainAccountPassword != String::new()
            {
                pyo3::prepare_freethreaded_python();
                Python::with_gil(|py| {
                    let code = std::fs::read_to_string("initiatorInterface.py").unwrap();
                    pyo3::prepare_freethreaded_python();
                    let activators = PyModule::from_code_bound(py, &code, "initiatorInterface.py", "initatorInterface").unwrap();
                    let args = PyTuple::new_bound(py, &[
                        &initiatorJSONPath,
                        &CoinA_Price.to_string(),
                        &CoinB_Price.to_string()
                    ]);
                    let kwargs = PyDict::new_bound(py);
                    kwargs.set_item("crosschainpassword", &crossChainAccountPassword).unwrap();
                    match activators.getattr("GeneralizedENC_FinalizationSubroutine_crossENCOnly").unwrap().call( &args, Some(&kwargs)) {
                            Ok(out) => {
                                // Handle the successful output
                                //let extract: String
                                    //= out.extract().expect("error getting traceback to string");
                                dbg!(out,); //extract);
                            }
                            Err(err) => {
                                // Handle the exception and print the traceback
                                let traceback_module = PyModule::import_bound(py, "traceback").unwrap();
                                let traceback_obj = traceback_module.getattr("format_exception").unwrap();
                                let exc_tb = err.traceback_bound(py);
                                println!("{}{}", exc_tb.unwrap().format().unwrap(), err);

                            }
                        }
                });
                tokio::spawn(async move {
                    pyo3::prepare_freethreaded_python();
                    Python::with_gil(|py| {
                        let code = std::fs::read_to_string("initiatorInterface.py").unwrap();
                        pyo3::prepare_freethreaded_python();
                        let activators = PyModule::from_code_bound(py, &code, "initiatorInterface.py", "initatorInterface").unwrap();
                        let args = PyTuple::new_bound(py, &[
                            &initiatorJSONPath,
                        ]);
                        let kwargs = PyDict::new_bound(py);
                        kwargs.set_item("crosschainpassword", &crossChainAccountPassword).unwrap();
                        match activators.getattr("GeneralizedENC_InitiatorClaimSubroutine_crossENCOnly").unwrap().call( &args, Some(&kwargs)) {
                            Ok(out) => {
                                // Handle the successful output
                                 //let extract: String
                                    //= out.extract().expect("error getting traceback to string");
                                dbg!(out,); //extract);
                            }
                            Err(err) => {
                                // Handle the exception and print the traceback
                                let traceback_module = PyModule::import_bound(py, "traceback").unwrap();
                                let traceback_obj = traceback_module.getattr("format_exception").unwrap();
                                let exc_tb = err.traceback_bound(py);
                                println!("{}{}", exc_tb.unwrap().format().unwrap(), err);

                            }
                        }
                    });
                });
            }
            else if localChainAccountPassword != String::new() && crossChainAccountPassword == String::new()
            {
                pyo3::prepare_freethreaded_python();
                Python::with_gil(|py| {
                    let code = std::fs::read_to_string("initiatorInterface.py").unwrap();
                    pyo3::prepare_freethreaded_python();
                    let activators = PyModule::from_code_bound(py, &code, "initiatorInterface.py", "initatorInterface").unwrap();
                    let args = PyTuple::new_bound(py, &[
                        &initiatorJSONPath,
                        &CoinA_Price.to_string(),
                        &CoinB_Price.to_string()
                    ]);
                    let kwargs = PyDict::new_bound(py);
                    kwargs.set_item("localchainpassword", &localChainAccountPassword).unwrap();
                    match activators.getattr("GeneralizedENC_FinalizationSubroutine_localENCOnly").unwrap().call( &args, Some(&kwargs)) {
                            Ok(out) => {
                                // Handle the successful output
                                 //let extract: String
                                    //= out.extract().expect("error getting traceback to string");
                                dbg!(out,); //extract);
                            }
                            Err(err) => {
                                // Handle the exception and print the traceback
                                let traceback_module = PyModule::import_bound(py, "traceback").unwrap();
                                let traceback_obj = traceback_module.getattr("format_exception").unwrap();
                                let exc_tb = err.traceback_bound(py);
                                println!("{}{}", exc_tb.unwrap().format().unwrap(), err);

                            }
                        }
                });
                tokio::spawn(async move {
                    pyo3::prepare_freethreaded_python();
                    Python::with_gil(|py| {
                        let code = std::fs::read_to_string("initiatorInterface.py").unwrap();
                        pyo3::prepare_freethreaded_python();
                        let activators = PyModule::from_code_bound(py, &code, "initiatorInterface.py", "initatorInterface").unwrap();
                        let args = PyTuple::new_bound(py, &[
                            &initiatorJSONPath,
                        ]);
                        let kwargs = PyDict::new_bound(py);
                        kwargs.set_item("localchainpassword", &localChainAccountPassword).unwrap();
                        match activators.getattr("GeneralizedENC_InitiatorClaimSubroutine_localENCOnly").unwrap()
                            .call( &args, Some(&kwargs)) {
                            Ok(out) => {
                                // Handle the successful output
                                 //let extract: String
                                    //= out.extract().expect("error getting traceback to string");
                                dbg!(out,); //extract);
                            }
                            Err(err) => {
                                // Handle the exception and print the traceback
                                let traceback_module = PyModule::import_bound(py, "traceback").unwrap();
                                let traceback_obj = traceback_module.getattr("format_exception").unwrap();
                                let exc_tb = err.traceback_bound(py);
                                println!("{}{}", exc_tb.unwrap().format().unwrap(), err);

                            }
                        }
                    });
                });
            }
            else
            {
                pyo3::prepare_freethreaded_python();
                Python::with_gil(|py| {
                    let code = std::fs::read_to_string("initiatorInterface.py").unwrap();
                    let activators = PyModule::from_code_bound(py, &code, "initiatorInterface.py", "initatorInterface").unwrap();
                    let args = PyTuple::new_bound(py, &[
                        &initiatorJSONPath,
                        &CoinA_Price.to_string(),
                        &CoinB_Price.to_string()
                    ]);
                    let kwargs = PyDict::new_bound(py);
                    kwargs.set_item(
                        "crosschainpassword", &crossChainAccountPassword
                    ).unwrap();
                    kwargs.set_item(
                        "localchainpassword", &localChainAccountPassword
                    ).unwrap();
                    match activators.getattr("GeneralizedENC_FinalizationSubroutine").unwrap().call( &args, Some(&kwargs)) {
                            Ok(out) => {
                                // Handle the successful output
                                //let extract: String
                                    //= out.extract().expect("error getting traceback to string");
                                dbg!(out,); //extract);
                            }
                            Err(err) => {
                                // Handle the exception and print the traceback
                                let traceback_module = PyModule::import_bound(py, "traceback").unwrap();
                                let traceback_obj = traceback_module.getattr("format_exception").unwrap();
                                let exc_tb = err.traceback_bound(py);
                                println!("{}{}", exc_tb.unwrap().format().unwrap(), err);

                            }
                        }
                });
                tokio::spawn(async move {
                    pyo3::prepare_freethreaded_python();
                    Python::with_gil(|py| {
                        let code = std::fs::read_to_string("initiatorInterface.py").unwrap();
                        pyo3::prepare_freethreaded_python();
                        let activators = PyModule::from_code_bound(py, &code, "initiatorInterface.py", "initatorInterface").unwrap();
                        let args = PyTuple::new_bound(py, &[
                            &initiatorJSONPath,
                        ]);
                        let kwargs = PyDict::new_bound(py);
                        kwargs.set_item(
                            "crosschainpassword", &crossChainAccountPassword
                        ).unwrap();
                        kwargs.set_item(
                            "localchainpassword", &localChainAccountPassword
                        ).unwrap();
                        match activators.getattr("GeneralizedENC_InitiatorClaimSubroutine").unwrap()
                            .call( &args, Some(&kwargs)) {
                            Ok(out) => {
                                // Handle the successful output
                                 //let extract: String
                                    //= out.extract().expect("error getting traceback to string");
                                dbg!(out,); //extract);
                            }
                            Err(err) => {
                                // Handle the exception and print the traceback
                                let traceback_module = PyModule::import_bound(py, "traceback").unwrap();
                                let traceback_obj = traceback_module.getattr("format_exception").unwrap();
                                let exc_tb = err.traceback_bound(py);
                                println!("{}{}", exc_tb.unwrap().format().unwrap(), err);

                            }
                        }
                    });
                });
            }

            let filepath = request.SwapTicketID.clone().unwrap() + "/ENC_finalization.bin";
            if !file_exists(&filepath) {
                println!("File does not exist yet, waiting...");
                wait_for_file(&filepath);
                println!("File found!");
            } else {
                println!("File already exists!");
            }
            let mut buffer = String::new(); // filecontents
            let mut file = fs::File::open(filepath.clone()).unwrap();
            file.read_to_string(&mut buffer).unwrap();
            set_swap_state(&request.SwapTicketID.clone().unwrap(), "finalized_submitted");
            return (status, Some(buffer.to_string()))
        }
    }
    if request.request_type == "logInToPasswordEncryptedAccount"
    {
        status = true;
        if request.Chain == None
        {
            let output = &(output.to_owned() + "Chain variable is required!");
            return (status, Some(output.to_string()));
        }
        if request.AccountName == None
        {
            let output = &(output.to_owned() + "AccountName variable is required!");
            return (status, Some(output.to_string()));
        }
        if request.Password == None
        {
            let output = &(output.to_owned() + "Password variable is required!");
            return (status, Some(output.to_string()));
        }
        else
        {
            let mut chainFrameworkPath = String::new();
            if request.Chain.clone().unwrap() == "TestnetErgo"
            {
                chainFrameworkPath = "Ergo/SigmaParticle/".to_string();
            }
            if request.Chain.clone().unwrap() == "Sepolia"
            {
                chainFrameworkPath = "EVM/Atomicity/".to_string();
            }
            let enc_env_path = chainFrameworkPath + &request.AccountName.clone().unwrap() + "/.env.encrypted";
            let mut pipe = Popen::create(&[
                "python3",  "-u", "main.py", "proveEncEnvFilePasswordKnowledge",
                &enc_env_path, &request.Password.clone().unwrap()
            ], PopenConfig{
                stdout: Redirection::Pipe, ..Default::default()}).expect("err");
            let (out, err) = pipe.communicate(None).expect("err");
            if let Some(exit_status) = pipe.poll()
            {
                println!("Out: {:?}, Err: {:?}", out, err);
                if out == Some("True\n".to_string())
                {
//                    println!("PasswordKnowledgeProven");
                    storage.loggedInAccountMap.write().insert(enc_env_path, request.Password.clone().unwrap());
                    dbg!(&storage.loggedInAccountMap);
                }
                //push success cases to loggedInAccountMap here
            }
            else
            {
                pipe.terminate().expect("err");
            }
            return (status, Some(out.expect("not string").to_string().replace("\n", "")))
        }
    }
    else
    {
        return  (status, Some("Unknown Error".to_string()));
    }
    }).await.unwrap()
}

fn file_exists(path: &str) -> bool {
    fs::metadata(path).is_ok()
}

fn wait_for_file(path: &str) {
    let poll_interval = Duration::from_secs(1); // Adjust as needed
    let timeout_duration = Duration::from_secs(30); // Adjust as needed
    let start_time = Instant::now();
    while !file_exists(path)
    { std::thread::sleep(poll_interval); continue; }
    return
}

fn remove_quotes(s: &str) -> String {
    s.trim_matches(|c| c == '\"' || c == '\'').to_string()
}

#[derive(Debug)]
pub struct Badapikey;
impl warp::reject::Reject for Badapikey {}

#[derive(Debug)]
pub struct Noapikey;
impl warp::reject::Reject for Noapikey {}

#[derive(Debug)]
pub struct Duplicateid;
impl warp::reject::Reject for Duplicateid {}

#[derive(Debug)]
pub struct Badrequesttype;
impl warp::reject::Reject for Badrequesttype {}


#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Id {
    id: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Request {
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
    MinVolCoinA: Option<String>,
    SwapTicketID: Option<String>,
    encryptedResponseBIN: Option<String>,
    QGChannel: Option<String>,
    AccountName: Option<String>,
    Password: Option<String>,
    Chain: Option<String>
    //ResponderJSONPath not ready yet
}

type StringStringMap = HashMap<String, String>;
type SingleNestMap = HashMap<String, HashMap<String, String>>;

#[derive(Clone)]
pub struct Storage {
   request_map: Arc<RwLock<StringStringMap>>,
   loggedInAccountMap: Arc<RwLock<StringStringMap>>,
   swapStateMap: Arc<RwLock<SingleNestMap>>
}

impl Storage {
    fn loggedInAccountMap_contains_key(&self, key: &str) -> bool{
        self.loggedInAccountMap.read().contains_key(key)
    }

    fn new() -> Self {
        Storage {
            request_map: Arc::new(RwLock::new(HashMap::new())),
            loggedInAccountMap: Arc::new(RwLock::new(HashMap::new())),
            swapStateMap: Arc::new(RwLock::new(HashMap::new()))
        }
    }

    fn update_swap_state_map(&mut self, loaded_map: SingleNestMap) -> Result<(), Box<dyn std::error::Error>> {
        // Replace the swapStateMap
//        let mut swap_state_map = self.swapStateMap.write();
//        *swap_state_map = loaded_map;
        *self.swapStateMap.write() = loaded_map;
        Ok(())
    }

}

