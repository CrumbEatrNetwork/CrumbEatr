import { exec } from "./command";

export default async function setup(): Promise<void> {
    console.log("Global setup routine starting");

    const canisterId = "bkyz2-fmaaa-aaaaa-qaaaq-cai";

    try {
        console.log("Adding controller to canister...");
        exec(
            "dfx canister update-settings crumbeatr --add-controller " + canisterId,
        );
        console.log("Controller added successfully");

        console.log("Calling reset on canister...");
        exec("dfx canister call crumbeatr reset");
        console.log("Reset called successfully");
        
        // Wait a bit to ensure the reset has fully processed
        console.log("Waiting for reset to complete...");
        await new Promise(resolve => setTimeout(resolve, 1000));
    } catch (error) {
        console.error("Setup error:", error);
        throw error;
    }

    const webServerPort = exec("dfx info webserver-port");
    const baseURL = `http://${canisterId}.localhost:${webServerPort}`;
    process.env["BASE_URL"] = baseURL;
    console.log("Global setup completed, BASE_URL:", baseURL);
}
