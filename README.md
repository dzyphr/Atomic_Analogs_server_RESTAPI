# Atomic Analogs Server REST API


#### Rust Warp based REST API for Swap Market coordinator / initiator 



## NOTE: Project is in Alpha / Testnet Phase 
## Actively Seeking Contributions and Feedback

## Key Features

* Private Function Endpoints
  - requestEncryptedInitiation
  - submitEncryptedResponse
* Public Function Endpoints
  - publishNewOrderType
* URL Endpoints 
  - version: v0.0.1
  - main_path: requests
  - public_main_path: publicrequests
  - OrderTypesPath: ordertypes


## How To Build

#### Ubuntu:

To clone and build this application, you'll need:
[Git](https://git-scm.com)
and
[Rustup](https://rustup.rs/) or [Cargo](https://github.com/rust-lang/cargo)

Keep in mind if this id Alpha software that will have lots bugs in it still.
 

```bash
# Clone this repository
$ git clone

# Go into the repository
$ cd Atomic_Analogs_server_RESTAPI

# Run cargo build
$ cargo build --release

# binary will be built in target/release/AASwapServerRESTAPI

```

* Related Software:
  - [AtomicAPI](https://github.com/dzyphr/atomicAPI)  
  - [Atomic_Analogs_client_RESTAPI](https://github.com/dzyphr/Atomic_Analogs_client_RESTAPI) 
  - [AtomicLocalWebUI](https://github.com/dzyphr/AtomicAnalogsLocalWebU)


## License

GPL3

## Contact

Discord:
[AtomicAnalogs](https://discord.gg/VDJGszpW58)  | [Ergo](https://discord.gg/ergo-platform-668903786361651200)
