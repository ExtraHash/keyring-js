import chalk from "chalk";
import crypto from "crypto";
import { KeyRing } from "../src/Keyring";

const encodings: any = ["Uint8Array", "hex", "base64", "utf8"];

const messageData = crypto.randomBytes(32);

async function main() {
  const keyring = new KeyRing(":memory:");

  keyring.on("ready", () => {
    console.log("Keyring ready. Starting tests.");

    for (const encoding of encodings) {
      console.log("Beginning test of encoding " + chalk.bold(encoding));

      const message =
        encoding === "Uint8Array"
          ? Uint8Array.from(messageData)
          : messageData.toString(encoding);

      const sig = keyring.sign(message, encoding);
      const verified = keyring.verify(message, sig, keyring.getPub(), encoding);

      if (!verified) {
        console.log(
          chalk.yellow.bold(
            "Failed to verify signature for " + encoding + " encoding!"
          )
        );
        process.exit(1);
      } else {
        console.log(chalk.green.bold(encoding + " tests passed."));
      }
    }

    process.exit(0);
  });

  keyring.init();
}

main();
