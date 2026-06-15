import './app.css'
import App from './App.svelte'
import init, { bcore_decrypt_wasm, sign_message_wasm } from '../../wasm/pkg'

async function main() {
  await init();

  const app = new App({
    target: document.getElementById('app')!,
    props: {
      bcore_decrypt_wasm: bcore_decrypt_wasm,
      sign_message_wasm: sign_message_wasm,
    }
  })
}

main();
