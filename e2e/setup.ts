import { exec } from "./command";

export default async function setup(): Promise<void> {
    console.debug("Global setup routine");

    const canisterId = "bkyz2-fmaaa-aaaaa-qaaaq-cai";

    exec(
        "dfx canister update-settings crumbeatr --add-controller " + canisterId,
    );
    exec("dfx canister call crumbeatr reset");

    const webServerPort = exec("dfx info webserver-port");
    const baseURL = `http://${canisterId}.localhost:${webServerPort}`;
    process.env["BASE_URL"] = baseURL;
}
