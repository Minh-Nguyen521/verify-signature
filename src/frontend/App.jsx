import { useState } from "react";
import { ec as EC } from "elliptic";
import CryptoJS from "crypto-js";
import "./App.css";
import config from "./config";
import { Buffer } from "buffer";
import { ethers } from "ethers";

function App() {
  const [msg, setMsg] = useState("");
  const ec = new EC("secp256k1");
  const keypair = ec.genKeyPair();

  const IP = config.IP;
  const Port = config.Port;

  const onChange = (e) => {
    setMsg(e.target.value);
  };

  const publicKeyToAddress = (pubKey) => {
    // Convert the public key to an Ethereum address
    const address = ethers.utils.computeAddress(pubKey);
    console.log("Address: ", address);
  };

  const onClick = () => {
    const hashMsg = CryptoJS.SHA256(msg).toString();
    const signature = keypair.sign(hashMsg);

    // console.log(signature);
    publicKeyToAddress(keypair.getPublic("array"));

    // Convert signature to hex
    const signatureHex = {
      r: signature.r.toString(16),
      s: signature.s.toString(16),
    };

    // console.log(signatureHex);

    SendtoSever(signatureHex, hashMsg);
  };

  const SendtoSever = async (signatureHex, hashMsg) => {
    // Convert public key to base64
    const publicKeyBase64 = Buffer.from(keypair.getPublic("array")).toString(
      "base64"
    );

    const response = await fetch(`http://${IP}${Port}/verify`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        signature: signatureHex,
        hashmessage: hashMsg,
        publickey: publicKeyBase64,
      }),
    });

    if (response.ok) {
      const data = await response.json();
      console.log("Data: ", data.valid);
      console.log("Address: ", data.address);
    } else {
      console.log("Error");
    }
  };

  return (
    <div>
      <input placeholder="Input" value={msg} onChange={onChange}></input>
      <button onClick={onClick}>Verify</button>
    </div>
  );
}

export default App;
