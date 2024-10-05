import { useState } from "react";
import { ec as EC } from "elliptic";
import CryptoJS from "crypto-js";
import "./App.css";
import config from "./config";

function App() {
  const [msg, setMsg] = useState("");
  const ec = new EC("secp256k1");
  const keypair = ec.genKeyPair();

  const IP = config.IP;
  const Port = config.Port;

  const onChange = (e) => {
    setMsg(e.target.value);
  };

  const onClick = () => {
    console.log("Value: ", msg);

    const hashMsg = CryptoJS.SHA256(msg).toString();
    const signature = keypair.sign(hashMsg);

    console.log(signature);

    // Convert signature to hex
    const signatureHex = {
      r: signature.r.toString(16),
      s: signature.s.toString(16),
    };

    console.log(signatureHex);

    const address = SendtoSever(signatureHex, hashMsg);
    // console.log("Address: ", address);
  };

  const SendtoSever = async (signatureHex, hashMsg) => {
    const response = await fetch(`http://${IP}${Port}/verify`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        signature: signatureHex,
        hashmessage: hashMsg,
        publickey: keypair.getPublic().encode("hex"),
      }),
    });

    if (response.ok) {
      const data = await response.json();
      console.log("Data: ", data.valid);
      // setAddress(data.address);
    }

    // return Address;
  };

  return (
    <div>
      <input placeholder="Input" value={msg} onChange={onChange}></input>
      <button onClick={onClick}>Verify</button>
    </div>
  );
}

export default App;
