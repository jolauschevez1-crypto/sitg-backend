-- Ejecuta esto en PostgreSQL para reforzar la tabla de usuarios.
-- Si ya tienes correos repetidos, corrígelos antes de crear la restricción UNIQUE.

ALTER TABLE usuario
ADD CONSTRAINT usuario_correo_unique UNIQUE (correo);

-- Opcional: asegúrate de que exista la columna para la foto de perfil.
ALTER TABLE usuario
ADD COLUMN IF NOT EXISTS foto_perfil TEXT;
