import './app.css'
import App from './App.svelte'
import { bcore_decrypt_wasm } from '../../wasm/pkg'


const app = new App({
  target: document.getElementById('app'),
  props: {
    bcore_decrypt_wasm: bcore_decrypt_wasm,
  }
})

export default app
