# SQP Financing

Aplicación estática conectada a Supabase Auth y PostgreSQL. GitHub Actions publica automáticamente la rama main en GitHub Pages.

## Configuración

1. Crea la cuenta inicial en Supabase Auth.
2. Asigna el rol ADMIN en SQL Editor:

   update public.sqp_profiles
   set role = 'ADMIN'
   where email = 'tu-correo@empresa.com';

3. Cuando GitHub Pages muestre la URL, agrégala en Supabase → Authentication → URL Configuration como Site URL y URL permitida de redirección.
4. Crea las demás cuentas desde Supabase Auth y asigna sus roles en public.sqp_profiles.

La clave publishable de index.html está diseñada para uso en navegador. No agregues una clave secret/service_role ni credenciales privadas.

El esquema y las políticas están en supabase/setup.sql. La base ya se aplicó al proyecto Supabase SQP-Financing.

