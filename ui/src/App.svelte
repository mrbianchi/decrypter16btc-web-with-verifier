<script lang="ts">
  import { saveAs } from 'file-saver';

  export let bcore_decrypt_wasm: ( password: string) => boolean;

  // Intentamos cargar los valores del LocalStorage, o usamos valores por defecto si no hay nada guardado.
  let password = localStorage.getItem('password') || "";
  let intentos = localStorage.getItem('intentos') || "";
  let bitcoinAddr: boolean = false;
  let lastAttemptedPassword = "";
  let feedbackMessage = "";

  const intentar = ( password: string) => {
    if(password.length === 0)
      return false;
    
    // Add the new attempt to the multiline string if it's not already there
    if (!intentos.includes(password)) {
      intentos = intentos + (intentos.length > 0 ? '\n' : '') + password;
      localStorage.setItem('intentos', intentos);
    }
    
    let r = bcore_decrypt_wasm(password);
    if(r) {
      feedbackMessage = "¡Éxito! La palabra es correcta.";
      alert("Lo lograste!");
    } else {
      feedbackMessage = "Error: La palabra no es correcta.";
      console.log("Decryption failed");
    }
    bitcoinAddr = r;
    lastAttemptedPassword = password;
    return r;
  }

  // Save password to localStorage when it changes
  $: {
    localStorage.setItem('password', password);
    if (password !== lastAttemptedPassword) {
      feedbackMessage = "";
    }
  }

  function descargarIntentos() {
    const blob = new Blob([intentos], {type: "text/plain;charset=utf-8"});
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
  <div>
    Intentos: {intentos.split('\n').length} ({intentos.length} bytes)
    <br>
    <button on:click={descargarIntentos}>Descargar intentos</button>
  </div>

</main>

<style>
  input {
    width: 100%;
    text-align: center;
  }

  * {
    font-family: 'Courier New', Courier, monospace;
    font-size: larger;
  }

  .feedback {
    margin-top: 1rem;
    text-align: center;
    font-weight: bold;
  }

  .success {
    color: green;
  }

  .error {
    color: red;
  }

  button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
</style>
