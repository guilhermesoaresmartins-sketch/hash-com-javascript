// ---------------------------------------------------------
// Elementos da página
// ---------------------------------------------------------
const campoSenha = document.getElementById("senha");
const botaoInverter = document.getElementById("inverter");
const chips = document.getElementById("chips");
const saida1 = document.getElementById("r1");
const saida2 = document.getElementById("r2");
const botaoGerar = document.getElementById("gerar");
const saida3 = document.getElementById("r3");
const blocoVerificar = document.getElementById("verificar");
const campoTentativa = document.getElementById("tentativa");
const botaoVerifica = document.getElementById("verifica");
const status = document.getElementById("status");

// ---------------------------------------------------------
// 1) Soma ASCII: a ordem das letras NÃO importa
// ---------------------------------------------------------
function calculaHash(senha) {
  let valor = 0;
  for (const letra of senha) {
    valor = valor + letra.codePointAt(0);
  }
  return valor;
}

// ---------------------------------------------------------
// 2) djb2: a ordem das letras importa
// ---------------------------------------------------------
function meuHash(senha) {
  let valor = 5381;
  for (const letra of senha) {
    valor = valor * 33 + letra.codePointAt(0);
    valor = valor % 2 ** 32;
  }
  return valor;
}

// ---------------------------------------------------------
// 3) PBKDF2 com salt (Web Crypto API, que é assíncrona)
// ---------------------------------------------------------
const ITERACOES = 200000;

function paraHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function deHex(texto) {
  return Uint8Array.from(texto.match(/.{2}/g), (h) => parseInt(h, 16));
}

async function derivaHash(senha, salt) {
  const chave = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(senha),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: salt, iterations: ITERACOES, hash: "SHA-256" },
    chave,
    256
  );
  return paraHex(new Uint8Array(bits));
}

async function hashSeguro(senha) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await derivaHash(senha, salt);
  return paraHex(salt) + ":" + hash;
}

async function verifica(senha, guardado) {
  const [saltHex, hashHex] = guardado.split(":");
  const novo = await derivaHash(senha, deHex(saltHex));
  return novo === hashHex;
}

// ---------------------------------------------------------
// Tela
// ---------------------------------------------------------
const LIMITE_CHIPS = 24;
let guardado = "";

function desenhaChips(senha) {
  chips.replaceChildren();

  if (senha === "") {
    const aviso = document.createElement("span");
    aviso.className = "vazio";
    aviso.textContent = "Digite uma senha acima.";
    chips.appendChild(aviso);
    return;
  }

  const letras = Array.from(senha);
  letras.slice(0, LIMITE_CHIPS).forEach((letra) => {
    const chip = document.createElement("div");
    chip.className = "chip";

    const simbolo = document.createElement("b");
    simbolo.textContent = letra === " " ? "␣" : letra;

    const codigo = document.createElement("small");
    codigo.textContent = letra.codePointAt(0);

    chip.append(simbolo, codigo);
    chips.appendChild(chip);
  });

  if (letras.length > LIMITE_CHIPS) {
    const resto = document.createElement("span");
    resto.className = "vazio";
    resto.textContent = "+" + (letras.length - LIMITE_CHIPS) + " letras";
    chips.appendChild(resto);
  }
}

function atualiza() {
  const senha = campoSenha.value;
  desenhaChips(senha);

  if (senha === "") {
    saida1.textContent = "—";
    saida2.textContent = "—";
    return;
  }

  saida1.textContent = calculaHash(senha);
  saida2.textContent = meuHash(senha);
}

botaoInverter.addEventListener("click", () => {
  campoSenha.value = Array.from(campoSenha.value).reverse().join("");
  atualiza();
  campoSenha.focus();
});

botaoGerar.addEventListener("click", async () => {
  const senha = campoSenha.value;
  if (senha === "") {
    saida3.textContent = "Digite uma senha no campo de cima.";
    return;
  }

  if (!window.crypto || !crypto.subtle) {
    saida3.textContent =
      "Seu navegador bloqueou a Web Crypto. Abra a página por https ou localhost.";
    return;
  }

  botaoGerar.disabled = true;
  saida3.textContent = "Calculando...";
  try {
    guardado = await hashSeguro(senha);
    saida3.textContent = guardado;
    blocoVerificar.hidden = false;
    status.textContent = "";
    status.className = "status";
  } catch (erro) {
    saida3.textContent = "Não deu pra gerar o hash: " + erro.message;
  } finally {
    botaoGerar.disabled = false;
  }
});

botaoVerifica.addEventListener("click", async () => {
  if (guardado === "") return;

  botaoVerifica.disabled = true;
  status.textContent = "Verificando...";
  status.className = "status";
  try {
    const bateu = await verifica(campoTentativa.value, guardado);
    status.textContent = bateu ? "Senha correta." : "Senha errada.";
    status.className = "status " + (bateu ? "ok" : "erro");
  } catch (erro) {
    status.textContent = "Não deu pra verificar: " + erro.message;
    status.className = "status erro";
  } finally {
    botaoVerifica.disabled = false;
  }
});

campoSenha.addEventListener("input", atualiza);
atualiza();
