use crate::{readJSONfromfilepath, json, Path, File, Storage, Html, Read};
pub async fn get_starterAPIKeys() -> Result<impl warp::Reply, warp::Rejection>
{
    let filepath = "starterAPIKeys.json";
    readJSONfromfilepath(filepath).await
}


pub async fn get_ElGamalPubs() -> Result<impl warp::Reply, warp::Rejection>
{
    let filepath = "ElGamalPubKeys.json";
    readJSONfromfilepath(filepath).await
}

pub async fn get_ElGamalQGChannels() -> Result<impl warp::Reply, warp::Rejection>
{
    let filepath = "ElGamalQGChannels.json";
    readJSONfromfilepath(filepath).await
}

pub async fn get_QGPubkeyArray() -> Result<impl warp::Reply, warp::Rejection>
{
    let filepath = "QGPubkeyArray.json";
    readJSONfromfilepath(filepath).await
}

pub async fn get_ordertypes() -> Result<impl warp::Reply, warp::Rejection>
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

pub async fn private_get_request_map( storage: Storage, apikey: Html<&str> ) -> Result<impl warp::Reply, warp::Rejection> 
{
        let result = storage.request_map.read();
        Ok(warp::reply::json(&*result))
}

