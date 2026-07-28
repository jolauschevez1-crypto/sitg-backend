const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const pool = require('./db');
const path = require('path');
const fs = require('fs');
const multer = require('multer');

cargarVariablesEntorno();

const app = express();
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || 'cambia_este_secreto_en_el_archivo_env';
const TOKEN_DURACION_SEGUNDOS = 60 * 60 * 24 * 7;

const origenesPermitidos = (process.env.CORS_ORIGIN || '*')
    .split(',')
    .map((origen) => origen.trim())
    .filter(Boolean);

app.use(
    cors({
        origin: (origin, callback) => {
            if (!origin || origenesPermitidos.includes('*') || origenesPermitidos.includes(origin)) {
                return callback(null, true);
            }
            return callback(new Error('Origen no permitido por CORS'));
        },
    }),
);
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(limitarPeticiones({ ventanaMs: 15 * 60 * 1000, maximo: 250 }));

const carpetaUploads = path.join(__dirname, 'uploads');
const carpetaPerfiles = path.join(carpetaUploads, 'perfiles');

if (!fs.existsSync(carpetaPerfiles)) {
    fs.mkdirSync(carpetaPerfiles, { recursive: true });
}

app.use('/uploads', express.static(carpetaUploads));

const almacenamientoPerfil = multer.diskStorage({
    destination: (req, file, callback) => callback(null, carpetaPerfiles),
    filename: (req, file, callback) => {
        const idUsuario = Number(req.params.id);
        const extensionPorMime = {
            'image/jpeg': '.jpg',
            'image/jpg': '.jpg',
            'image/png': '.png',
            'image/webp': '.webp',
            'image/heic': '.heic',
            'image/heif': '.heif',
        };

        const extensionOriginal = path
            .extname(file.originalname || '')
            .toLowerCase();

        let extension = extensionPorMime[file.mimetype] || extensionOriginal || '.jpg';

        if (extension === '.jpeg') {
            extension = '.jpg';
        }

        const extensionesPermitidas = ['.jpg', '.jpeg', '.png', '.webp', '.heic', '.heif'];

        if (!extensionesPermitidas.includes(extension)) {
            extension = '.jpg';
        }

        callback(null, `usuario_${idUsuario}_${Date.now()}${extension}`);
    },
});

const filtroImagen = (req, file, callback) => {
    const tiposPermitidos = [
        'image/jpeg',
        'image/jpg',
        'image/png',
        'image/webp',
        'image/heic',
        'image/heif',
        'application/octet-stream',
    ];

    const extensionesPermitidas = [
        '.jpg',
        '.jpeg',
        '.png',
        '.webp',
        '.heic',
        '.heif',
    ];

    const extensionOriginal = path
        .extname(file.originalname || '')
        .toLowerCase();

    const mimePermitido = tiposPermitidos.includes(file.mimetype);
    const extensionPermitida = extensionesPermitidas.includes(extensionOriginal);

    if (!mimePermitido && !extensionPermitida) {
        return callback(
            new Error('Solo se permiten imágenes JPG, PNG, WEBP, HEIC o HEIF')
        );
    }

    callback(null, true);
};

const subirFotoPerfil = multer({
    storage: almacenamientoPerfil,
    fileFilter: filtroImagen,
    limits: { fileSize: 5 * 1024 * 1024 },
});

/* ==========================
   SALUD DEL SERVIDOR
========================== */
app.get('/', (req, res) => {
    res.json({ success: true, message: 'API Turismo Guayaquil activa' });
});

app.get('/health', async(req, res) => {
    try {
        await pool.query('SELECT 1');
        return res.json({ success: true, database: 'ok' });
    } catch (error) {
        console.error('ERROR HEALTH:', error);
        return res.status(500).json({ success: false, message: 'La base de datos no responde' });
    }
});

/* ==========================
   REGISTRO
========================== */
app.post('/register', async(req, res) => {
    const datos = limpiarUsuario(req.body);
    const errorValidacion = validarUsuario(datos, { requierePassword: true });

    if (errorValidacion) {
        return res.status(400).json({ success: false, message: errorValidacion });
    }

    try {
        const hash = await bcrypt.hash(datos.contraseña, 10);

        const result = await pool.query(
            `INSERT INTO usuario
        (nombre, apellido, correo, "contraseña", telefono)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id_usuario, nombre, apellido, correo, telefono, foto_perfil`, [datos.nombre, datos.apellido, datos.correo, hash, datos.telefono],
        );

        return res.status(201).json({
            success: true,
            message: 'Cuenta creada correctamente',
            usuario: result.rows[0],
            user: result.rows[0],
        });
    } catch (err) {
        console.error('ERROR REGISTRO:', err);

        if (err.code === '23505') {
            return res.status(409).json({ success: false, message: 'El correo ya está registrado' });
        }

        return res.status(500).json({ success: false, message: 'No se pudo crear la cuenta' });
    }
});

/* ==========================
   LOGIN
========================== */
app.post('/login', limitarPeticiones({ ventanaMs: 15 * 60 * 1000, maximo: 30 }), async(req, res) => {
    const correo = normalizarCorreo(req.body.correo);

    const contraseña = String(
        req.body.contraseña ||
        req.body.contrasena ||
        req.body.password ||
        ''
    );

    if (!correo || !contraseña) {
        return res.status(400).json({
            success: false,
            message: 'Ingrese correo y contraseña'
        });
    }
    try {
        const result = await pool.query('SELECT * FROM usuario WHERE LOWER(correo) = $1', [correo]);

        if (result.rows.length === 0) {
            return res.status(401).json({ success: false, message: 'Correo o contraseña incorrectos' });
        }

        const user = result.rows[0];
        const contraseñaGuardada = String(user['contraseña'] || '');
        let ok = false;

        if (contraseñaGuardada.startsWith('$2')) {
            ok = await bcrypt.compare(contraseña, contraseñaGuardada);
        } else {
            ok = contraseña === contraseñaGuardada;

            if (ok) {
                const nuevoHash = await bcrypt.hash(contraseña, 10);
                await pool.query('UPDATE usuario SET "contraseña" = $1 WHERE id_usuario = $2', [
                    nuevoHash,
                    user.id_usuario,
                ]);
            }
        }

        if (!ok) {
            return res.status(401).json({ success: false, message: 'Correo o contraseña incorrectos' });
        }

        delete user['contraseña'];

        const token = crearToken({
            id_usuario: user.id_usuario,
            id: user.id_usuario,
            correo: user.correo,
        });

        return res.json({
            success: true,
            message: 'Inicio de sesión correcto',
            token,
            usuario: user,
            user,
        });
    } catch (err) {
        console.error('ERROR LOGIN:', err);
        return res.status(500).json({ success: false, message: 'No se pudo iniciar sesión' });
    }
});

app.get('/me', autenticarToken, async(req, res) => {
    try {
        const result = await pool.query(
            `SELECT id_usuario, nombre, apellido, correo, telefono, foto_perfil
       FROM usuario
       WHERE id_usuario = $1`, [req.usuario.id_usuario],
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'Usuario no encontrado' });
        }

        return res.json({ success: true, usuario: result.rows[0], user: result.rows[0] });
    } catch (error) {
        console.error('ERROR ME:', error);
        return res.status(500).json({ success: false, message: 'No se pudo cargar el usuario' });
    }
});

/* ==========================
   PERFIL
========================== */
app.get('/user/:id', autenticarToken, validarMismoUsuario, async(req, res) => {
    try {
        const result = await pool.query(
            `SELECT id_usuario, nombre, apellido, correo, telefono, foto_perfil
       FROM usuario
       WHERE id_usuario = $1`, [req.params.id],
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'Usuario no encontrado' });
        }

        return res.json({ success: true, usuario: result.rows[0], user: result.rows[0] });
    } catch (err) {
        console.error('ERROR PERFIL:', err);
        return res.status(500).json({ success: false, message: 'No se pudo cargar el perfil' });
    }
});

app.put('/user/:id', autenticarToken, validarMismoUsuario, async(req, res) => {
    const datos = limpiarUsuario(req.body);
    const errorValidacion = validarUsuario(datos, { requierePassword: false });

    if (errorValidacion) {
        return res.status(400).json({ success: false, message: errorValidacion });
    }

    try {
        const result = await pool.query(
            `UPDATE usuario
       SET nombre = $1,
           apellido = $2,
           correo = $3,
           telefono = $4
       WHERE id_usuario = $5
       RETURNING id_usuario, nombre, apellido, correo, telefono, foto_perfil`, [datos.nombre, datos.apellido, datos.correo, datos.telefono, req.params.id],
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'Usuario no encontrado' });
        }

        return res.json({ success: true, usuario: result.rows[0], user: result.rows[0] });
    } catch (err) {
        console.error('ERROR ACTUALIZAR PERFIL:', err);

        if (err.code === '23505') {
            return res.status(409).json({ success: false, message: 'El correo ya está registrado' });
        }

        return res.status(500).json({ success: false, message: 'No se pudo actualizar el perfil' });
    }
});

/* ==========================
   HISTORIA
========================== */
app.get('/historia', async(req, res) => {
    try {
        const [portadaResult, datosClaveResult, eventosResult, curiosidadesResult] = await Promise.all([
            pool.query(`
        SELECT
          id_historia_portada,
          titulo,
          subtitulo,
          imagen,
          titulo_introduccion,
          descripcion_introduccion,
          icono_introduccion,
          titulo_datos_clave,
          titulo_linea_tiempo,
          subtitulo_linea_tiempo,
          titulo_curiosidades
        FROM historia_portada
        WHERE activo = TRUE
        ORDER BY id_historia_portada DESC
        LIMIT 1
      `),
            pool.query(`
        SELECT id_dato_clave, valor, etiqueta, icono, orden
        FROM historia_datos_clave
        WHERE activo = TRUE
        ORDER BY orden ASC, id_dato_clave ASC
      `),
            pool.query(`
        SELECT id_evento, fecha, titulo, descripcion, icono, orden
        FROM historia_eventos
        WHERE activo = TRUE
        ORDER BY orden ASC, id_evento ASC
      `),
            pool.query(`
        SELECT id_curiosidad, texto, orden
        FROM historia_curiosidades
        WHERE activo = TRUE
        ORDER BY orden ASC, id_curiosidad ASC
      `),
        ]);

        return res.json({
            portada: portadaResult.rows.length > 0 ? portadaResult.rows[0] : null,
            datos_clave: datosClaveResult.rows,
            eventos: eventosResult.rows,
            curiosidades: curiosidadesResult.rows,
        });
    } catch (error) {
        console.error('ERROR HISTORIA:', error);
        return res.status(500).json({ message: 'Error al obtener la historia' });
    }
});

/* ==========================
   CULTURA
========================== */
app.get('/cultura', async(req, res) => {
    try {
        const result = await pool.query(`
      SELECT id_cultura, titulo, descripcion, imagen, id_admin
      FROM cultura
      ORDER BY id_cultura
    `);

        return res.json(result.rows);
    } catch (err) {
        console.error('ERROR CULTURA:', err);
        return res.status(500).json({ message: 'No se pudo cargar cultura' });
    }
});

/* ==========================
   GASTRONOMÍA
========================== */
app.get('/gastronomia', async(req, res) => {
    try {
        const result = await pool.query('SELECT * FROM gastronomia ORDER BY id_gastronomia');
        return res.json(result.rows);
    } catch (err) {
        console.error('ERROR GASTRONOMIA:', err);
        return res.status(500).json({ message: 'No se pudo cargar gastronomía' });
    }
});

app.get('/gastronomia/:id', async(req, res) => {
    const idGastronomia = Number(req.params.id);

    if (!Number.isInteger(idGastronomia) || idGastronomia <= 0) {
        return res.status(400).json({ success: false, message: 'ID de gastronomía inválido' });
    }

    try {
        const result = await pool.query(
            `SELECT *
       FROM gastronomia
       WHERE id_gastronomia = $1`, [idGastronomia],
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'Gastronomía no encontrada' });
        }

        return res.json({ success: true, gastronomia: result.rows[0] });
    } catch (err) {
        console.error('ERROR DETALLE GASTRONOMIA:', err);
        return res.status(500).json({ success: false, message: 'No se pudo cargar gastronomía' });
    }
});

/* ==========================
   LUGARES
========================== */
app.get('/lugares', async(req, res) => {
    try {
        const result = await pool.query('SELECT * FROM lugar_turistico ORDER BY id_lugar');
        return res.json(result.rows);
    } catch (err) {
        console.error('ERROR LUGARES:', err);
        return res.status(500).json({ message: 'No se pudieron cargar lugares' });
    }
});

app.get('/lugares/:id', async(req, res) => {
    const idLugar = Number(req.params.id);

    if (!Number.isInteger(idLugar) || idLugar <= 0) {
        return res.status(400).json({ success: false, message: 'ID de lugar inválido' });
    }

    try {
        const result = await pool.query(
            `SELECT *
       FROM lugar_turistico
       WHERE id_lugar = $1`, [idLugar],
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'Lugar no encontrado' });
        }

        return res.json({ success: true, lugar: result.rows[0] });
    } catch (err) {
        console.error('ERROR DETALLE LUGAR:', err);
        return res.status(500).json({ success: false, message: 'No se pudo cargar el lugar' });
    }
});

app.get('/lugar-recomendado', async(req, res) => {
    try {
        const result = await pool.query(`
      SELECT *
      FROM lugar_turistico
      ORDER BY RANDOM()
      LIMIT 1
    `);

        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'No hay lugares registrados' });
        }

        return res.json({ success: true, lugar: result.rows[0] });
    } catch (error) {
        console.error('ERROR LUGAR RECOMENDADO:', error);
        return res.status(500).json({ success: false, message: 'No se pudo cargar el lugar recomendado' });
    }
});

/* ==========================
   TOURS
========================== */
app.get('/tours', async(req, res) => {
    try {
        const resultado = await pool.query(`
      SELECT id_tour, id_categoria, nombre, descripcion, fecha, cupos, precio
      FROM tour
      ORDER BY fecha ASC
    `);

        return res.json(resultado.rows);
    } catch (error) {
        console.error('ERROR TOURS:', error);
        return res.status(500).json({ success: false, message: 'No se pudieron cargar los tours' });
    }
});

app.get('/tours/:id', async(req, res) => {
    const idTour = Number(req.params.id);

    if (!Number.isInteger(idTour) || idTour <= 0) {
        return res.status(400).json({ success: false, message: 'ID de tour inválido' });
    }

    try {
        const resultado = await pool.query(
            `SELECT id_tour, id_categoria, nombre, descripcion, fecha, cupos, precio
       FROM tour
       WHERE id_tour = $1`, [idTour],
        );

        if (resultado.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'Tour no encontrado' });
        }

        return res.json({ success: true, tour: resultado.rows[0] });
    } catch (error) {
        console.error('ERROR DETALLE TOUR:', error);
        return res.status(500).json({ success: false, message: 'No se pudo cargar el tour' });
    }
});

/* ==========================
   FAVORITOS EN BASE DE DATOS
========================== */
app.get('/favoritos', autenticarToken, async(req, res) => {
    const idUsuario = obtenerIdUsuario(req);

    try {
        const resultado = await pool.query(
            `SELECT
         uf.id_favorito,
         uf.tipo,
         uf.id_elemento,
         uf.fecha_creacion,
         CASE
           WHEN uf.tipo = 'lugar' THEN to_jsonb(lt)
           WHEN uf.tipo = 'gastronomia' THEN to_jsonb(g)
           WHEN uf.tipo = 'tour' THEN to_jsonb(t)
           ELSE '{}'::jsonb
         END AS item
       FROM favorito uf
       LEFT JOIN lugar_turistico lt
         ON uf.tipo = 'lugar' AND uf.id_elemento = lt.id_lugar
       LEFT JOIN gastronomia g
         ON uf.tipo = 'gastronomia' AND uf.id_elemento = g.id_gastronomia
       LEFT JOIN tour t
         ON uf.tipo = 'tour' AND uf.id_elemento = t.id_tour
       WHERE uf.id_usuario = $1
       ORDER BY uf.fecha_creacion DESC`, [idUsuario],
        );

        const favoritos = resultado.rows.map(construirFavoritoDesdeFila);

        return res.json({ success: true, favoritos });
    } catch (error) {
        return manejarErrorFavoritos(error, res, 'No se pudieron cargar los favoritos');
    }
});

app.get('/favoritos/:tipo/:id', autenticarToken, async(req, res) => {
    const datos = validarFavorito(req.params.tipo, req.params.id);

    if (datos.error) {
        return res.status(400).json({ success: false, message: datos.error });
    }

    try {
        const resultado = await pool.query(
            `SELECT 1
       FROM favorito
       WHERE id_usuario = $1 AND tipo = $2 AND id_elemento = $3
       LIMIT 1`, [obtenerIdUsuario(req), datos.tipo, datos.idElemento],
        );

        return res.json({ success: true, favorito: resultado.rows.length > 0 });
    } catch (error) {
        return manejarErrorFavoritos(error, res, 'No se pudo consultar el favorito');
    }
});

app.post('/favoritos', autenticarToken, async(req, res) => {
    const datos = validarFavorito(req.body.tipo, req.body.id_elemento || req.body.idElemento || req.body.id || req.body.id_lugar || req.body.id_gastronomia || req.body.id_tour);

    if (datos.error) {
        return res.status(400).json({ success: false, message: datos.error });
    }

    const idUsuario = obtenerIdUsuario(req);

    try {
        const existeElemento = await existeElementoFavorito(datos.tipo, datos.idElemento);

        if (!existeElemento) {
            return res.status(404).json({ success: false, message: 'El elemento no existe' });
        }

        const favoritoActual = await pool.query(
            `SELECT id_favorito
       FROM favorito
       WHERE id_usuario = $1 AND tipo = $2 AND id_elemento = $3`, [idUsuario, datos.tipo, datos.idElemento],
        );

        if (favoritoActual.rows.length > 0) {
            await pool.query(
                `DELETE FROM favorito
         WHERE id_usuario = $1 AND tipo = $2 AND id_elemento = $3`, [idUsuario, datos.tipo, datos.idElemento],
            );

            return res.json({
                success: true,
                favorito: false,
                message: 'Favorito eliminado',
            });
        }

        await pool.query(
            `INSERT INTO favorito (id_usuario, tipo, id_elemento)
       VALUES ($1, $2, $3)
       ON CONFLICT (id_usuario, tipo, id_elemento) DO NOTHING`, [idUsuario, datos.tipo, datos.idElemento],
        );

        return res.status(201).json({
            success: true,
            favorito: true,
            message: 'Favorito agregado',
        });
    } catch (error) {
        return manejarErrorFavoritos(error, res, 'No se pudo guardar el favorito');
    }
});

app.delete('/favoritos/:tipo/:id', autenticarToken, async(req, res) => {
    const datos = validarFavorito(req.params.tipo, req.params.id);

    if (datos.error) {
        return res.status(400).json({ success: false, message: datos.error });
    }

    try {
        await pool.query(
            `DELETE FROM favorito
       WHERE id_usuario = $1 AND tipo = $2 AND id_elemento = $3`, [obtenerIdUsuario(req), datos.tipo, datos.idElemento],
        );

        return res.json({
            success: true,
            favorito: false,
            message: 'Favorito eliminado',
        });
    } catch (error) {
        return manejarErrorFavoritos(error, res, 'No se pudo eliminar el favorito');
    }
});

/* ==========================
   FOTO DE PERFIL
========================== */
app.post('/usuarios/:id/foto', autenticarToken, validarMismoUsuario, subirFotoPerfil.single('foto'), async(req, res) => {
    try {
        const idUsuario = Number(req.params.id);

        if (!Number.isInteger(idUsuario) || idUsuario <= 0) {
            await eliminarArchivoSeguro(req.file ? req.file.path : null);
            return res.status(400).json({ success: false, message: 'ID de usuario inválido' });
        }

        if (!req.file) {
            return res.status(400).json({ success: false, message: 'Debe seleccionar una imagen' });
        }

        const usuarioAnterior = await pool.query('SELECT foto_perfil FROM usuario WHERE id_usuario = $1', [idUsuario]);

        if (usuarioAnterior.rows.length === 0) {
            await eliminarArchivoSeguro(req.file.path);
            return res.status(404).json({ success: false, message: 'Usuario no encontrado' });
        }

        const fotoAnterior = usuarioAnterior.rows[0].foto_perfil;

        const resultado = await pool.query(
            `UPDATE usuario
       SET foto_perfil = $1
       WHERE id_usuario = $2
       RETURNING id_usuario, nombre, apellido, correo, telefono, foto_perfil`, [req.file.filename, idUsuario],
        );

        if (fotoAnterior) {
            const rutaFotoAnterior = path.join(carpetaPerfiles, path.basename(fotoAnterior));
            if (rutaFotoAnterior !== req.file.path) {
                await eliminarArchivoSeguro(rutaFotoAnterior);
            }
        }

        const fotoUrl = `${req.protocol}://${req.get('host')}/uploads/perfiles/${req.file.filename}`;

        return res.json({
            success: true,
            message: 'Foto actualizada correctamente',
            usuario: resultado.rows[0],
            foto_url: fotoUrl,
        });
    } catch (error) {
        console.error('ERROR FOTO PERFIL:', error);
        await eliminarArchivoSeguro(req.file ? req.file.path : null);
        return res.status(500).json({ success: false, message: 'No se pudo guardar la foto' });
    }
});

app.delete('/usuarios/:id/foto', autenticarToken, validarMismoUsuario, async(req, res) => {
    try {
        const idUsuario = Number(req.params.id);

        if (!Number.isInteger(idUsuario) || idUsuario <= 0) {
            return res.status(400).json({ success: false, message: 'ID de usuario inválido' });
        }

        const resultadoUsuario = await pool.query('SELECT foto_perfil FROM usuario WHERE id_usuario = $1', [idUsuario]);

        if (resultadoUsuario.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'Usuario no encontrado' });
        }

        const fotoPerfil = resultadoUsuario.rows[0].foto_perfil;

        await pool.query('UPDATE usuario SET foto_perfil = NULL WHERE id_usuario = $1', [idUsuario]);

        if (fotoPerfil) {
            await eliminarArchivoSeguro(path.join(carpetaPerfiles, path.basename(fotoPerfil)));
        }

        return res.json({ success: true, message: 'Foto eliminada correctamente' });
    } catch (error) {
        console.error('ERROR ELIMINAR FOTO:', error);
        return res.status(500).json({ success: false, message: 'No se pudo eliminar la foto' });
    }
});

/* ==========================
   MANEJO DE ERRORES
========================== */
app.use((error, req, res, next) => {
    if (error instanceof multer.MulterError) {
        if (error.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ success: false, message: 'La imagen no puede superar los 5 MB' });
        }

        return res.status(400).json({ success: false, message: error.message });
    }

    if (error) {
        console.error('ERROR GENERAL:', error);
        return res.status(400).json({ success: false, message: error.message || 'Solicitud inválida' });
    }

    next();
});

app.use((req, res) => {
    res.status(404).json({ success: false, message: 'Ruta no encontrada' });
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Servidor ejecutándose en el puerto ${PORT}`);
});

/* ==========================
   FUNCIONES AUXILIARES
========================== */
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

function normalizarCorreo(correo) {
    return String(correo || '').trim().toLowerCase();
}

function limpiarUsuario(body) {
    return {
        nombre: String(body.nombre || '').trim(),
        apellido: String(body.apellido || '').trim(),
        correo: normalizarCorreo(body.correo),
        contraseña: String(body.contraseña || ''),
        telefono: String(body.telefono || '').trim(),
    };
}

function validarUsuario(datos, { requierePassword }) {
    if (datos.nombre.length < 2) return 'Ingrese un nombre válido';
    if (datos.apellido.length < 2) return 'Ingrese un apellido válido';
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(datos.correo)) return 'Ingrese un correo válido';
    if (datos.telefono && !/^[0-9+\-\s]{7,15}$/.test(datos.telefono)) return 'Ingrese un teléfono válido';
    if (requierePassword && datos.contraseña.length < 6) return 'La contraseña debe tener al menos 6 caracteres';
    return null;
}

function base64Url(valor) {
    return Buffer.from(valor).toString('base64url');
}

function crearFirma(data) {
    return crypto.createHmac('sha256', JWT_SECRET).update(data).digest('base64url');
}

function crearToken(payload) {
    const header = { alg: 'HS256', typ: 'JWT' };
    const ahora = Math.floor(Date.now() / 1000);
    const cuerpo = {...payload, iat: ahora, exp: ahora + TOKEN_DURACION_SEGUNDOS };
    const unsigned = `${base64Url(JSON.stringify(header))}.${base64Url(JSON.stringify(cuerpo))}`;
    return `${unsigned}.${crearFirma(unsigned)}`;
}

function verificarToken(token) {
    const partes = String(token || '').split('.');
    if (partes.length !== 3) return null;

    const [header, payload, firma] = partes;
    const unsigned = `${header}.${payload}`;
    const firmaEsperada = crearFirma(unsigned);

    const bufferFirma = Buffer.from(firma);
    const bufferEsperada = Buffer.from(firmaEsperada);

    if (bufferFirma.length !== bufferEsperada.length || !crypto.timingSafeEqual(bufferFirma, bufferEsperada)) {
        return null;
    }

    try {
        const datos = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
        const ahora = Math.floor(Date.now() / 1000);

        if (!datos.exp || datos.exp < ahora) return null;
        return datos;
    } catch (_) {
        return null;
    }
}

function autenticarToken(req, res, next) {
    const encabezado = req.headers.authorization || req.headers.Authorization || '';
    const token = encabezado.startsWith('Bearer ') ? encabezado.slice(7) : encabezado;

    if (!token) {
        return res.status(401).json({ success: false, message: 'Token no proporcionado' });
    }

    const usuario = verificarToken(token);

    if (!usuario) {
        return res.status(401).json({ success: false, message: 'Sesión inválida o expirada' });
    }

    req.usuario = usuario;
    next();
}

function validarMismoUsuario(req, res, next) {
    const idParametro = Number(req.params.id);

    if (!Number.isInteger(idParametro) || idParametro <= 0) {
        return res.status(400).json({ success: false, message: 'ID inválido' });
    }

    const idToken = Number(req.usuario.id_usuario || req.usuario.id);

    if (idToken !== idParametro) {
        return res.status(403).json({ success: false, message: 'No tiene permiso para modificar este usuario' });
    }

    next();
}


function obtenerIdUsuario(req) {
    return Number(
        (req.usuario && (req.usuario.id_usuario || req.usuario.id)) ||
        (req.user && (req.user.id_usuario || req.user.id)) ||
        0
    );
}

function limitarPeticiones({ ventanaMs, maximo }) {
    const intentos = new Map();

    return (req, res, next) => {
        const clave = req.ip || req.socket.remoteAddress || 'desconocido';
        const ahora = Date.now();
        const registro = intentos.get(clave) || { inicio: ahora, total: 0 };

        if (ahora - registro.inicio > ventanaMs) {
            registro.inicio = ahora;
            registro.total = 0;
        }

        registro.total += 1;
        intentos.set(clave, registro);

        if (registro.total > maximo) {
            return res.status(429).json({ success: false, message: 'Demasiados intentos. Intente más tarde.' });
        }

        next();
    };
}


function normalizarTipoFavorito(tipo) {
    const valor = String(tipo || '').trim().toLowerCase();

    if (valor === 'lugares') return 'lugar';
    if (valor === 'plato' || valor === 'comida' || valor === 'gastronomias' || valor === 'gastronomía') return 'gastronomia';
    if (valor === 'tours') return 'tour';

    return valor;
}

function validarFavorito(tipoRaw, idRaw) {
    const tipo = normalizarTipoFavorito(tipoRaw);
    const idElemento = Number(idRaw);

    if (!['lugar', 'gastronomia', 'tour'].includes(tipo)) {
        return { error: 'Tipo de favorito inválido' };
    }

    if (!Number.isInteger(idElemento) || idElemento <= 0) {
        return { error: 'ID de favorito inválido' };
    }

    return { tipo, idElemento };
}

async function existeElementoFavorito(tipo, idElemento) {
    let consulta;

    if (tipo === 'lugar') {
        consulta = 'SELECT 1 FROM lugar_turistico WHERE id_lugar = $1 LIMIT 1';
    } else if (tipo === 'gastronomia') {
        consulta = 'SELECT 1 FROM gastronomia WHERE id_gastronomia = $1 LIMIT 1';
    } else if (tipo === 'tour') {
        consulta = 'SELECT 1 FROM tour WHERE id_tour = $1 LIMIT 1';
    } else {
        return false;
    }

    const resultado = await pool.query(consulta, [idElemento]);
    return resultado.rows.length > 0;
}

function construirFavoritoDesdeFila(fila) {
    const item = fila.item && typeof fila.item === 'object' ? {...fila.item } : {};

    item.__id_favorito = fila.id_favorito;
    item.__tipo_favorito = fila.tipo;
    item.__clave_favorito = `${fila.tipo}:${fila.id_elemento}`;
    item.__fecha_favorito = fila.fecha_creacion;

    return item;
}

function manejarErrorFavoritos(error, res, mensaje) {
    console.error('ERROR FAVORITOS:', error);

    if (error.code === '42P01') {
        return res.status(500).json({
            success: false,
            message: 'Falta crear la tabla de favoritos. Ejecute backend/sql/favoritos.sql en PostgreSQL.',
        });
    }

    return res.status(500).json({ success: false, message: mensaje });
}

async function eliminarArchivoSeguro(rutaArchivo) {
    if (!rutaArchivo) return;

    try {
        if (fs.existsSync(rutaArchivo)) {
            await fs.promises.unlink(rutaArchivo);
        }
    } catch (error) {
        console.error('No se pudo eliminar archivo:', error.message);
    }
}