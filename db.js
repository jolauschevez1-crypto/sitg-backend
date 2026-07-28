const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');

cargarVariablesEntorno();

const pool = new Pool({
  user: process.env.DB_USER || 'postgres',
  host: process.env.DB_HOST || 'localhost',
  database: process.env.DB_NAME || 'turismo_guayaquil',
  password: process.env.DB_PASSWORD || '',
  port: Number(process.env.DB_PORT || 5432),
});

module.exports = pool;

function cargarVariablesEntorno() {
  const rutaEnv = path.join(__dirname, '.env');

  if (!fs.existsSync(rutaEnv)) return;

  const contenido = fs.readFileSync(rutaEnv, 'utf8');

  for (const linea of contenido.split(/\r?\n/)) {
    const limpia = linea.trim();
    if (!limpia || limpia.startsWith('#') || !limpia.includes('=')) continue;

    const indice = limpia.indexOf('=');
    const clave = limpia.slice(0, indice).trim();
    let valor = limpia.slice(indice + 1).trim();

    if ((valor.startsWith('"') && valor.endsWith('"')) || (valor.startsWith("'") && valor.endsWith("'"))) {
      valor = valor.slice(1, -1);
    }

    if (!process.env[clave]) {
      process.env[clave] = valor;
    }
  }
}
