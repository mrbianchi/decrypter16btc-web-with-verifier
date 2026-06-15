<script lang="ts">
  import { saveAs } from 'file-saver';

  export let bcore_decrypt_wasm: (password: string) => string;
  export let sign_message_wasm: (message: string) => string;

  // Intentamos cargar los valores del LocalStorage, o usamos valores por defecto si no hay nada guardado.
  let password = localStorage.getItem('password') || "";
  let intentos = localStorage.getItem('intentos') || "";
  let bitcoinAddr: boolean = false;
  let lastAttemptedPassword = "";
  let feedbackMessage = "";
  let decryptedCkey: string | null = null;
  let pubkeyHex: string | null = null;

  // Firma
  let messageToSign = localStorage.getItem('messageToSign') || "";
  let signResult: string | null = null;
  let signError: string | null = null;
  let signingInProgress = false;

  const intentar = (password: string) => {
    if (password.length === 0)
      return false;

    // Add the new attempt to the multiline string if it's not already there
    if (!intentos.includes(password)) {
      intentos = intentos + (intentos.length > 0 ? '\n' : '') + password;
      localStorage.setItem('intentos', intentos);
    }

    let jsonStr = bcore_decrypt_wasm(password);
    let result: { success: boolean; error?: string; ckey_decrypted?: string; pubkey?: string };

    try {
      result = JSON.parse(jsonStr);
    } catch (e) {
      feedbackMessage = "Error: respuesta inválida del WASM.";
      bitcoinAddr = false;
      lastAttemptedPassword = password;
      decryptedCkey = null;
      pubkeyHex = null;
      signResult = null;
      signError = null;
      return false;
    }

    if (result.success) {
      feedbackMessage = "¡Éxito! La contraseña es correcta.";
      bitcoinAddr = true;
      decryptedCkey = result.ckey_decrypted || null;
      pubkeyHex = result.pubkey || null;
    } else {
      feedbackMessage = `Error: ${result.error || 'La contraseña no es correcta.'}`;
      bitcoinAddr = false;
      decryptedCkey = null;
      pubkeyHex = null;
      signResult = null;
      signError = null;
    }

    lastAttemptedPassword = password;
    return result.success;
  }

  const firmarMensaje = () => {
    if (!messageToSign.trim()) {
      signError = "Por favor ingresa un mensaje para firmar.";
      signResult = null;
      return;
    }
    if (!decryptedCkey) {
      signError = "Primero debes desencriptar exitosamente la ckey.";
      signResult = null;
      return;
    }

    signingInProgress = true;
    signError = null;
    signResult = null;

    let jsonStr = sign_message_wasm(messageToSign);
    let result: { success: boolean; error?: string; signature_hex?: string; message?: string };

    try {
      result = JSON.parse(jsonStr);
    } catch (e) {
      signError = "Error: respuesta inválida del WASM al firmar.";
      signingInProgress = false;
      return;
    }

    if (result.success) {
      signResult = result.signature_hex || null;
      signError = null;
    } else {
      signError = result.error || "Error desconocido al firmar.";
      signResult = null;
    }

    signingInProgress = false;
  }

  // Save password to localStorage when it changes
  $: {
    localStorage.setItem('password', password);
    if (password !== lastAttemptedPassword) {
      feedbackMessage = "";
    }
  }

  $: {
    localStorage.setItem('messageToSign', messageToSign);
  }

  function descargarIntentos() {
    const blob = new Blob([intentos], { type: "text/plain;charset=utf-8" });
    saveAs(blob, "intentos.txt");
  }
</script>

<main>
  <div class="card">
    <h3>Manual Finder</h3>
    <p><input placeholder="password" bind:value={password} on:keydown={(e) => e.key === 'Enter' && intentar(password)} /></p>
    <button on:click={() => intentar(password)} disabled={password === lastAttemptedPassword}>Intentar</button>
    {#if feedbackMessage}
      <p class="feedback" class:success={bitcoinAddr} class:error={!bitcoinAddr}>{feedbackMessage}</p>
    {/if}
  </div>

  {#if bitcoinAddr && decryptedCkey}
    <div class="card signing-card">
      <h3>Firmar Mensaje</h3>
      {#if pubkeyHex}
        <p class="pubkey-display">Pubkey: <code>{pubkeyHex}</code></p>
      {/if}
      <p>
        <textarea
          placeholder="Mensaje a firmar..."
          bind:value={messageToSign}
          rows="4"
          class="sign-input"
        ></textarea>
      </p>
      <button on:click={firmarMensaje} disabled={signingInProgress}>
        {signingInProgress ? "Firmando..." : "Firmar Mensaje"}
      </button>
      {#if signResult}
        <div class="sign-result">
          <p class="success">¡Firma generada exitosamente!</p>
          <p><strong>Firma (DER hex):</strong></p>
          <pre class="signature-hex">{signResult}</pre>
        </div>
      {/if}
      {#if signError}
        <p class="feedback error">{signError}</p>
      {/if}
    </div>
  {/if}

  <div class="footer-area">
    Intentos: {intentos.split('\n').length} ({intentos.length} bytes)
    <br>
    <button on:click={descargarIntentos}>Descargar intentos</button>
  </div>

</main>

<style>
  :global(body) {
    margin: 0;
    display: flex;
    place-items: center;
    min-width: 320px;
    min-height: 100vh;
  }

  :global(#app) {
    width: 100%;
    max-width: 720px;
    margin: 0 auto;
    padding: 2rem;
    text-align: center;
  }

  main {
    color: #e0e0e0;
  }

  h3 {
    color: #ffffff;
    margin-top: 0;
  }

  input {
    width: 100%;
    text-align: center;
    background: #2a2a2a;
    color: #e0e0e0;
    border: 1px solid #555;
    padding: 0.6em;
    border-radius: 6px;
    font-family: 'Courier New', Courier, monospace;
    font-size: larger;
    box-sizing: border-box;
  }

  textarea.sign-input {
    width: 100%;
    font-family: 'Courier New', Courier, monospace;
    font-size: smaller;
    padding: 0.5rem;
    resize: vertical;
    background: #2a2a2a;
    color: #e0e0e0;
    border: 1px solid #555;
    border-radius: 6px;
    box-sizing: border-box;
  }

  button {
    border-radius: 8px;
    border: 1px solid #555;
    padding: 0.6em 1.2em;
    font-size: 1em;
    font-weight: 500;
    font-family: 'Courier New', Courier, monospace;
    background-color: #3a3a3a;
    color: #e0e0e0;
    cursor: pointer;
    transition: border-color 0.25s;
  }

  button:hover {
    border-color: #646cff;
  }

  button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  * {
    font-family: 'Courier New', Courier, monospace;
    font-size: larger;
  }

  .card {
    margin-bottom: 2rem;
  }

  .signing-card {
    border: 1px solid #555;
    padding: 1.5rem;
    border-radius: 8px;
    background: #1e1e1e;
    color: #e0e0e0;
    text-align: left;
  }

  .signing-card h3 {
    color: #ffffff;
    text-align: center;
  }

  .signing-card button {
    background-color: #2e7d32;
    color: #ffffff;
    border: 1px solid #388e3c;
    width: 100%;
  }

  .signing-card button:hover {
    background-color: #388e3c;
    border-color: #4caf50;
  }

  .signing-card button:disabled {
    background-color: #3a3a3a;
    border-color: #555;
    opacity: 0.5;
  }

  .feedback {
    margin-top: 1rem;
    text-align: center;
    font-weight: bold;
  }

  .success {
    color: #4caf50;
  }

  .error {
    color: #ef5350;
  }

  .pubkey-display {
    text-align: center;
    word-break: break-all;
    font-size: smaller;
    color: #b0b0b0;
    margin-bottom: 1rem;
  }

  .pubkey-display code {
    font-size: smaller;
    background: #2a2a2a;
    color: #ffab40;
    padding: 0.2rem 0.5rem;
    border-radius: 4px;
    word-break: break-all;
  }

  .sign-result {
    margin-top: 1rem;
    text-align: center;
    color: #e0e0e0;
  }

  .sign-result strong {
    color: #b0b0b0;
  }

  .signature-hex {
    background: #2a2a2a;
    color: #81c784;
    padding: 0.75rem;
    border-radius: 4px;
    word-break: break-all;
    white-space: pre-wrap;
    font-size: small;
    max-height: 200px;
    overflow-y: auto;
    text-align: left;
    border: 1px solid #444;
    margin: 0.5rem 0;
  }

  .footer-area {
    margin-top: 2rem;
    color: #888;
    font-size: 0.85em;
  }

  .footer-area button {
    font-size: 0.85em;
    margin-top: 0.5rem;
  }
</style>