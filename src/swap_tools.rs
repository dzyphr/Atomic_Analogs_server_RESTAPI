use crate::{HashMap, fs, SingleNestMap, insert_into_nested_map, is_directory, File, is_file, Write, StringStringMap, Uuid, Path, Value, Storage, checkAccountLoggedInStatus, Popen, PopenConfig, Redirection};

pub fn set_swap_state(swapName: &str, state: &str) -> bool
{
    let PossibleSwapStatesInitiator = vec!["initiating", "initiated_unsubmitted", "initiated_submitted", "responded", "verifying_response", "verified_response", "finalizing", "finalized_unsubmitted", "finalized_submitted", "claiming", "refunding", "claimed", "refunded", "terminated", "tbd"];
    if !PossibleSwapStatesInitiator.contains(&state)
    {
        dbg!("Please provide valid state argument choice.\nChoices: initiated, uploadingResponseContract, fundingResponseContract, responded, finalized, verifyingFinalizedContractValues, claiming, refunding, claimed, refunded, terminated, tbd");
        return false
    }
    if !is_directory(&swapName)
    {
        dbg!("Swap directory named: ".to_owned() +  swapName +  "not found!\nMake sure swap dir is created before setting it's state.");
        return false
    }
    let mut map = load_local_swap_state_map(); //handles creation of the map if its not there
    if map.contains_key(swapName)
    {
        map = insert_into_nested_map(&mut map, swapName, "SwapState", state)
    }
    else
    {
        let mut innermap: HashMap<String, String> = HashMap::new();
        innermap.insert("SwapState".to_string(), state.to_string());
        map.insert(swapName.to_string(), innermap);
    }
    update_local_swap_state_map(map);
    fs::write(swapName.to_owned() + "/SwapState", state).expect("error writing SwapState");
    return true;

}



pub fn update_local_swap_state_map(jsonmapdata: SingleNestMap)
{
    let swapStateMapString = serde_json::to_string_pretty(&jsonmapdata).unwrap();
    fs::write("SwapStateMap", swapStateMapString).expect("Unable to write file");
}

pub fn load_local_swap_state_map() -> SingleNestMap
{
    let filename = "SwapStateMap";
    if is_file(filename)
    {
        let contents = fs::read_to_string(filename).expect("cant read SwapStateMap");
        let map: SingleNestMap = serde_json::from_str(&contents).expect("cant parse SwapStateMap into serde_json object");
        return map
    }
    else
    {
        let mut file = File::create(filename.clone()).unwrap();
        let data = "{}";
        file.write_all(data.as_bytes()).unwrap() ;
        let contents = fs::read_to_string(filename).expect("cant read SwapStateMap");
        let map: SingleNestMap = serde_json::from_str(&contents).expect("cant parse SwapStateMap into serde_json object");
        return map

    }
}

pub fn check_swap_state_map_against_swap_dirs(mut map: SingleNestMap) -> SingleNestMap
{
    let current_dir = Path::new(".");
    let mut uuid_dirs = vec![];
    let mut swapstatemap = HashMap::<String, String>::new();
    if let Ok(subdirs) = fs::read_dir(current_dir)
    {
        for subdir in subdirs
        {
            if let Ok(subdir) = subdir
            {
                let file_name = subdir.file_name().to_string_lossy().into_owned();
                if let Some(name) = Some(file_name.clone())
                {
                    if let Ok(uuid) = Uuid::parse_str(&name.clone())
                    {
                        dbg!(&name.clone());
                        uuid_dirs.push(name.clone());
                        /*if uuid.get_version() == Some(uuid::Version::Md5) //this check for
                         * specific version doesnt currently work but is possible
                        {
                        }*/
                    }
                }
            }
        }
    };
    if uuid_dirs.is_empty()
    {
        if !map.is_empty()
        {
            map.clear();
        }
    }
    for dir in &uuid_dirs
    {
        if !map.contains_key(&dir.to_string())
        {
            let mut swapDataMap = StringStringMap::new();
        //    swapDataMap.insert("OrderTypeUUID".to_string(), request.OrderTypeUUID.clone().unwrap().replace("\\", "").replace("\"", ""));
        //    TODO add OrderTypeUUID to responder.json so we can add it in this instance\
            let init_J_filename = dir.clone().to_string() + "/initiator.json";

            if is_file(&init_J_filename)
            {
                let init_J: Value = serde_json::from_str(&fs::read_to_string(init_J_filename).expect("initiator json not found")).unwrap();
                let ElGamalKeyPath = init_J.get("ElGamalKeyPath").unwrap().to_string().replace("\\", "").replace("\"", "");
                dbg!(&ElGamalKeyPath);
                let ElGObj: Value = serde_json::from_str(&fs::read_to_string(ElGamalKeyPath).unwrap()).unwrap();
                let QGChannel = ElGObj.get("q").unwrap().to_string().replace("\\", "").replace("\"", "") + "," + &ElGObj.get("g").unwrap().to_string().replace("\\", "").replace("\"", "");
                swapDataMap.insert("QGChannel".to_string(), QGChannel);
                swapDataMap.insert("ElGamalKey".to_string(), ElGObj.get("Public Key").unwrap().to_string().replace("\\", "").replace("\"", ""));
                swapDataMap.insert("ClientElGamalKey".to_string(), init_J.get("ElGamalKey").unwrap().to_string().replace("\\", "").replace("\"", ""));
                swapDataMap.insert("ElGamalKeyPath".to_string(), init_J.get("ElGamalKeyPath").unwrap().to_string().replace("\\", "").replace("\"", ""));
                swapDataMap.insert("LocalChain".to_string(), init_J.get("LocalChain").unwrap().to_string().replace("\\", "").replace("\"", ""));
                swapDataMap.insert("CrossChain".to_string(), init_J.get("CrossChain").unwrap().to_string().replace("\\", "").replace("\"", ""));
                swapDataMap.insert("SwapRole".to_string(), init_J.get("SwapRole").unwrap().to_string().replace("\\", "").replace("\"", ""));
                swapDataMap.insert("SwapAmount".to_string(), init_J.get("SwapAmount").unwrap().to_string().replace("\\", "").replace("\"", ""));
                swapDataMap.insert("LocalChainAccount".to_string(), init_J.get("LocalChainAccount").unwrap().to_string().replace("\\", "").replace("\"", ""));
                swapDataMap.insert("CrossChainAccount".to_string(), init_J.get("CrossChainAccount").unwrap().to_string().replace("\\", "").replace("\"", ""));
                map.insert(dir.to_string(), swapDataMap);
            }
        }
    }
    for swap in map.clone().keys()
    {
        if !uuid_dirs.contains(&swap)
        {
            map.remove(&swap.clone()); //remove swaps that cant be found locally
        }
    }
    return map
}

pub async fn restore_state(mut storage: Storage)
{
    let mut loaded_swap_state_map = check_swap_state_map_against_swap_dirs(load_local_swap_state_map());
    storage.update_swap_state_map(loaded_swap_state_map.clone());
    for swap in storage.swapStateMap.read().clone().keys()
    {
        let mut localChainAccountPassword = String::new();
        let mut crossChainAccountPassword = String::new();
        let swapDataMap = storage.swapStateMap.read()[&swap.clone()].clone();
        let mut properlyLoggedIn = false;
        if swapDataMap["LocalChain"] == "TestnetErgo" && swapDataMap["CrossChain"] == "Sepolia"
        {
            let ErgoAccountName = &swapDataMap["LocalChainAccount"];
            let ergchainFrameworkPath = "Ergo/SigmaParticle/";
            let ergencEnvPath = ergchainFrameworkPath.to_owned() + &ErgoAccountName.clone() + "/.env.encrypted";
            let ergoencenvexists = if let Ok(_) = fs::metadata(ergencEnvPath.clone()) {
                true
            } else {
                false
            };
            let mut ErgoAccountPassword = String::new();
            let SepoliaAccountName =  &swapDataMap["CrossChainAccount"];
            let sepoliachainFrameworkPath = "EVM/Atomicity/";
            let sepoliaencEnvPath = sepoliachainFrameworkPath.to_owned() + &SepoliaAccountName.clone() + "/.env.encrypted";
            let sepoliaencenvexists = if let Ok(_) = fs::metadata(sepoliaencEnvPath.clone()) {
                true
            } else {
                false
            };
            let mut SepoliaAccountPassword = String::new();
            if ergoencenvexists && sepoliaencenvexists
            {
                if checkAccountLoggedInStatus(&ergencEnvPath, storage.clone()) == true
                {
                    localChainAccountPassword = storage.loggedInAccountMap.read()[&ergencEnvPath].clone();
                }
                else
                {
                    let errstr =  "TestnetErgo ".to_owned() +  &ErgoAccountName + " is not logged in!";
                    dbg!(&errstr);
                }
                if checkAccountLoggedInStatus(&sepoliaencEnvPath, storage.clone()) == true
                {
                    crossChainAccountPassword = storage.loggedInAccountMap.read()[&sepoliaencEnvPath].clone();
                }
                else
                {
                    let errstr =  "Sepolia ".to_owned() +  &SepoliaAccountName + " is not logged in!";
                    dbg!(&errstr);
                }
                if checkAccountLoggedInStatus(&sepoliaencEnvPath, storage.clone()) == true && checkAccountLoggedInStatus(&ergencEnvPath, storage.clone()) == true
                {
                    properlyLoggedIn = true;
                }
            }
            else
            {
                //TODO handle cases where one acc is encrypted and another is not
                properlyLoggedIn = true;
            }
        }
        if properlyLoggedIn == true
        {
            dbg!("reloading swap: ".to_string() +  &swap);
            let mut pipe = Popen::create(&[
                "python3",  "-u", "main.py", "watchSwapLoop", &swap,
                &localChainAccountPassword, &crossChainAccountPassword,
            ], PopenConfig{
                detached: true,
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
        }
    }
}

