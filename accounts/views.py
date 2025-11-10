# -*- coding: utf-8 -*-
from django.db import connection, IntegrityError
from django.http import HttpResponse
from django.utils.http import url_has_allowed_host_and_scheme
#from reportlab. lib.pagesizes import A4  # Importar e instalar reportlab si no está instalado, seccion de Actas deL arbitro 
from django.shortcuts import render, redirect
from django.contrib import messages
from django.urls import reverse
from django.core.paginator import Paginator
from django.shortcuts import render
from django.core.cache import cache
from django.views.decorators.cache import never_cache, cache_control
from django.db import transaction, IntegrityError

from django.contrib.auth.hashers import make_password
from .forms import LoginForm, RegistroUsuarioForm, AsignarRolForm, EditarCargoArbitralForm
from .utils import role_required

import re
import unicodedata
from datetime import date, datetime, time, timedelta, timezone

# ============================================================
# Helpers comunes (reutilizables en varios views)
# ============================================================

DIAS_NOMBRES = ["Domingo", "Lunes", "Martes", "Miércoles", "Jueves", "Viernes", "Sábado"]

def _normalize_role(s: str) -> str:
    """Lower + remover acentos para comparar roles ('Árbitro' == 'arbitro')."""
    if not s:
        return ""
    s = "".join(c for c in unicodedata.normalize("NFD", s) if unicodedata.category(c) != "Mn")
    return s.strip().lower()

def _parse_rut_from_session(request):
    """Extrae (rut, dv) de session o levanta ValueError."""
    rut_full = request.session.get("user_rut", "")
    rut, dv = rut_full.split("-")
    # normaliza y valida
    rut = str(int(str(rut).replace(".", "").strip()))
    dv = dv.strip().upper()
    return rut, dv


def _infer_rango_edad(nombre_serie:str, categoria:str):
    """
    Intenta inferir límite de edad desde 'Sub 17', 'Sub-13', etc.
    Retorna (min_edad, max_edad) donde cualquiera puede ser None si no hay info.
    """
    txt = f"{nombre_serie or ''} {categoria or ''}".lower()
    m = re.search(r"sub\s*-?\s*(\d{1,2})", txt)
    if m:
        max_e = int(m.group(1))
        # muchas ligas no definen mínimo; dejamos None
        return (None, max_e)
    # Si dice 'adulta' o 'senior' podrías fijar mínimos:
    if 'adulta' in txt or 'adulta' in txt:
        return (18, None)
    if 'senior' in txt:
        return (35, None)
    return (None, None)

def _calc_edad(fecha_nac):
    if not fecha_nac:
        return None
    today = date.today()
    years = today.year - fecha_nac.year - ((today.month, today.day) < (fecha_nac.month, fecha_nac.day))
    return years


def _valid_hhmm(s: str) -> bool:
    return bool(re.fullmatch(r"^[0-2]\d:[0-5]\d$", s))

def _order_by_time_nulls_last(alias: str = "p") -> str:
    """
    ORDER BY compatible para poner NULL al final sin 'NULLS LAST'.
    Ej.: ORDER BY p.fecha ASC, ({alias}.hora IS NULL) ASC, {alias}.hora ASC
    """
    return f"({alias}.hora IS NULL) ASC, {alias}.hora ASC"


# ============================================================
# LOGIN MANUAL CON SESIÓN
# ============================================================

@never_cache
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def login_view(request):
    if request.method == "POST":
        form = LoginForm(request.POST)
        if form.is_valid():
            rut_input = (form.cleaned_data.get("rut") or "").strip()
            password  = form.cleaned_data.get("contrasena") or ""

            # Normaliza "12.345.678-9"
            rut_limpio = rut_input.replace(".", "").upper()
            if "-" not in rut_limpio:
                messages.error(request, "Formato de RUT inválido. Use 12345678-9.")
                return render(request, "accounts/login.html", {"form": form})

            rut_numero, dv = rut_limpio.split("-", 1)
            rut_numero = rut_numero.strip()
            dv = dv.strip().upper()

            if not rut_numero.isdigit() or not (6 <= len(rut_numero) <= 8) or not (dv.isdigit() or dv == "K"):
                messages.error(request, "RUT/DV inválidos. Use 12345678-9 con DV 0-9 o K.")
                return render(request, "accounts/login.html", {"form": form})

            try:
                rut_int = int(rut_numero)
            except ValueError:
                messages.error(request, "RUT inválido.")
                return render(request, "accounts/login.html", {"form": form})

            try:
                with connection.cursor() as cursor:
                    cursor.execute("""
                        SELECT l.contrasena, l.estado, u.nombre, COALESCE(r.nombre_rol,'') AS nombre_rol, u.digitov
                          FROM login l
                          JOIN usuarios u 
                            ON u.rut = l.rut AND UPPER(u.digitov) = UPPER(l.digitov)
                     LEFT JOIN usuarios_roles ur 
                            ON ur.rut = u.rut AND UPPER(ur.digitov) = UPPER(u.digitov)
                     LEFT JOIN roles r 
                            ON r.rol_id = ur.rol_id
                         WHERE u.rut = %s AND UPPER(u.digitov) = UPPER(%s)
                         LIMIT 1;
                    """, [rut_int, dv])
                    data = cursor.fetchone()
            except Exception:
                messages.error(request, "Error de conexión con la base de datos.")
                return render(request, "accounts/login.html", {"form": form})

            if not data:
                messages.error(request, "RUT o contraseña incorrectos.")
                return render(request, "accounts/login.html", {"form": form})

            contrasena_db, estado, nombre, rol, dv_db = data

            if password != (contrasena_db or ""):
                messages.error(request, "Contraseña incorrecta.")
                return render(request, "accounts/login.html", {"form": form})

            if _normalize_role(estado) != "activo":
                messages.error(request, "Usuario inactivo.")
                return render(request, "accounts/login.html", {"form": form})

            # ===== Sesión limpia + set de flags de rol =====
            request.session.flush()                 # nueva sesión
            request.session.cycle_key()             # nueva clave de sesión

            rol_norm = _normalize_role(rol or "")
            request.session["user_rut"]        = f"{rut_int}-{dv_db}"
            request.session["user_rut_num"]    = rut_int
            request.session["user_dv"]         = (dv_db or "").upper()[:1]
            request.session["user_nombre"]     = nombre or ""
            request.session["user_rol"]        = rol or "Sin rol"

            # Flags por rol (para navbar/base.html)
            request.session["user_is_admin"]      = (rol_norm == "administrador")
            request.session["user_is_arbitro"]    = (rol_norm == "arbitro")
            request.session["user_is_turno"]      = (rol_norm == "turno")
            request.session["user_is_tribunal"]   = (rol_norm == "tribunal de disciplina")
            request.session["user_is_secretaria"] = (rol_norm in ("secretario", "secretaria"))

            # Otros flags usados en tu app
            request.session["BOOT_EPOCH"] = cache.get("BOOT_EPOCH")
            request.session["mostrar_bienvenida"] = True

            # Expiración: 8 horas sin actividad (ajusta a gusto)
            request.session.set_expiry(60 * 60 * 8)

            # Redirección por rol (respetando ?next= si es seguro)
            next_url = request.GET.get("next") or request.POST.get("next")
            if next_url and url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()}):
                return redirect(next_url)

            if request.session["user_is_admin"]:
                return redirect("dashboard")
            if request.session["user_is_arbitro"]:
                return redirect("perfil_arbitro")
            if request.session["user_is_tribunal"]:
                return redirect("panel_tribunal")
            if request.session["user_is_secretaria"]:
                return redirect("panel_secretaria")
            if request.session["user_is_turno"]:
                return redirect("panel_turno")

            messages.warning(request, "Tu rol no tiene un panel asignado. Serás redirigido al portal.")
            return redirect("home")

        else:
            messages.error(request, "Por favor, corrige los errores del formulario.")
    else:
        form = LoginForm()

    return render(request, "accounts/login.html", {"form": form})

# ============================================================
# LOGOUT
# ============================================================

def logout_view(request):
    request.session.flush()
    messages.info(request, "Sesión cerrada correctamente.")
    resp = redirect("login")
    resp["Cache-Control"] = "no-store"
    return resp


# ============================================================
# DASHBOARD (solo admin)
# ============================================================

@never_cache
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@role_required("Administrador")
def dashboard(request):
    if "user_rut" not in request.session:
        return redirect("login")

    user_nombre = request.session.get("user_nombre", "Usuario")
    user_rol = request.session.get("user_rol", "Sin rol")

    with connection.cursor() as cursor:
        # Usuarios con rol ACTIVO
        cursor.execute("""
            SELECT COUNT(DISTINCT (u.rut, UPPER(u.digitov)))
            FROM usuarios u
            JOIN usuarios_roles ur
              ON ur.rut = u.rut AND UPPER(ur.digitov) = UPPER(u.digitov)
            WHERE LOWER(ur.estado) = 'activo';
        """)
        usuarios_activos = cursor.fetchone()[0]

        # Usuarios INACTIVOS = sin rol o con rol marcado Inactivo
        cursor.execute("""
            SELECT COUNT(DISTINCT (u.rut, UPPER(u.digitov)))
            FROM usuarios u
            LEFT JOIN usuarios_roles ur
              ON ur.rut = u.rut AND UPPER(ur.digitov) = UPPER(u.digitov)
            WHERE ur.rut IS NULL OR LOWER(ur.estado) = 'inactivo';
        """)
        usuarios_inactivos = cursor.fetchone()[0]

        # Administradores con estado ACTIVO
        cursor.execute("""
            SELECT COUNT(DISTINCT (u.rut, UPPER(u.digitov)))
            FROM usuarios u
            JOIN usuarios_roles ur
              ON ur.rut = u.rut AND UPPER(ur.digitov) = UPPER(u.digitov)
            JOIN roles r
              ON r.rol_id = ur.rol_id
            WHERE LOWER(r.nombre_rol) = 'administrador'
              AND LOWER(ur.estado) = 'activo';
        """)
        administradores = cursor.fetchone()[0]

        # Árbitros con estado ACTIVO
        cursor.execute("""
            SELECT COUNT(DISTINCT (u.rut, UPPER(u.digitov)))
            FROM usuarios u
            JOIN usuarios_roles ur
              ON ur.rut = u.rut AND UPPER(ur.digitov) = UPPER(u.digitov)
            JOIN roles r
              ON r.rol_id = ur.rol_id
            WHERE LOWER(r.nombre_rol) = 'arbitro'
              AND LOWER(ur.estado) = 'activo';
        """)
        arbitros = cursor.fetchone()[0]

        # Partidos sin árbitro asignado (tu consulta original)
        cursor.execute("""
            SELECT COUNT(*)
            FROM partidos
            WHERE rut IS NULL
               OR digitov IS NULL
               OR TRIM(COALESCE(digitov, '')) = '';
        """)
        partidos_sin_arbitro = cursor.fetchone()[0]

    return render(request, "accounts/dashboard.html", {
        "user_nombre": user_nombre,
        "user_rol": user_rol,
        "usuarios_activos": usuarios_activos,
        "usuarios_inactivos": usuarios_inactivos,
        "administradores": administradores,
        "arbitros": arbitros,
        "partidos_sin_arbitro": partidos_sin_arbitro,
    })


# ============================================================
# REGISTRO DE USUARIO (solo admin)
# ============================================================

@never_cache
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def registrar_usuario(request):
    if request.method == "POST":
        form = RegistroUsuarioForm(request.POST)
        if form.is_valid():
            rut_raw = str(form.cleaned_data.get("rut") or "")
            rut_str = rut_raw.replace(".", "").replace("-", "").strip()
            dv      = str(form.cleaned_data.get("digitoV", "") or "").strip().upper()
            correo  = form.cleaned_data.get("correo")

            # =============================
            # Validaciones del RUT
            # =============================
            if not rut_str.isdigit():
                messages.error(request, "El RUT debe contener solo números (sin puntos ni guion).")
                return render(request, "accounts/registrar_usuario.html", {"form": form})

            if not (6 <= len(rut_str) <= 8):
                messages.error(request, "El RUT debe tener entre 6 y 8 dígitos.")
                return render(request, "accounts/registrar_usuario.html", {"form": form})

            try:
                rut_int = int(rut_str)
            except ValueError:
                messages.error(request, "El RUT ingresado es inválido.")
                return render(request, "accounts/registrar_usuario.html", {"form": form})

            if rut_int > 99999999:
                messages.error(request, "El RUT ingresado es inválido.")
                return render(request, "accounts/registrar_usuario.html", {"form": form})

            if len(dv) != 1:
                messages.error(request, "El dígito verificador debe ser un solo carácter (0-9 o K).")
                return render(request, "accounts/registrar_usuario.html", {"form": form})

            # =============================
            # Validaciones en la base de datos
            # =============================
            try:
                with connection.cursor() as cursor:
                    # Verificar RUT + DV duplicado
                    cursor.execute("""
                        SELECT COUNT(*)
                          FROM usuarios
                         WHERE rut = %s AND UPPER(digitov) = UPPER(%s);
                    """, [rut_int, dv])
                    if cursor.fetchone()[0] > 0:
                        messages.warning(request, f"⚠️ Ya existe un usuario con el RUT {rut_int}-{dv}.")
                        return render(request, "accounts/registrar_usuario.html", {"form": form})

                    # Verificar correo duplicado
                    cursor.execute("""
                        SELECT COUNT(*)
                          FROM usuarios
                         WHERE LOWER(correo) = LOWER(%s);
                    """, [correo])
                    if cursor.fetchone()[0] > 0:
                        messages.warning(request, f"⚠️ El correo '{correo}' ya está en uso.")
                        return render(request, "accounts/registrar_usuario.html", {"form": form})

                # =============================
                # Generar contraseña automática
                # =============================
                password_raw = rut_str[-4:]  # últimos 4 dígitos del RUT

                # =============================
                # Crear usuario mediante el Form
                # =============================
                form.save()  # el save() ya crea usuario y login con la contraseña automática

                messages.success(
                    request,
                    f"✅ Usuario {rut_int}-{dv} registrado correctamente. "
                    f"La contraseña inicial son los últimos 4 dígitos del RUT."
                )
                return redirect("dashboard")

            except IntegrityError as e:
                constraint = getattr(getattr(e, "__cause__", None), "diag", None)
                cname = getattr(constraint, "constraint_name", "") if constraint else ""
                msg = str(e)

                if "correo" in msg.lower() or "correo" in (cname or "").lower():
                    messages.error(request, f"⚠️ El correo '{correo}' ya está en uso.")
                elif "usuarios_pkey" in (cname or "").lower() or "rut" in msg.lower():
                    messages.error(request, f"⚠️ Ya existe un usuario con el RUT {rut_int} (independiente del DV).")
                else:
                    messages.error(request, f"❌ Error de integridad: {cname or msg}")
                return render(request, "accounts/registrar_usuario.html", {"form": form})

            except Exception as e:
                messages.error(request, f"❌ Error inesperado: {str(e)}")
                return render(request, "accounts/registrar_usuario.html", {"form": form})

        else:
            messages.error(request, "Por favor, corrige los errores del formulario.")
    else:
        form = RegistroUsuarioForm()

    return render(request, "accounts/registrar_usuario.html", {"form": form})


# ============================================================
# ASIGNAR ROL (solo admin)
# ============================================================

@never_cache
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@role_required("Administrador")
def asignar_rol(request):
    """
    Asignar/editar/eliminar rol de los usuarios.
    Valida RUT (6-8 dígitos), DV (1 char) y existencia de usuario/rol.
    """

    # =====================================================
    # POST → procesar formulario (asignar / editar / eliminar)
    # =====================================================
    if request.method == "POST":
        rut_num = (request.POST.get("rut_num") or "").replace(".", "").replace("-", "").strip()
        digitoV = (request.POST.get("digitoV") or "").strip().upper()
        rol_id  = (request.POST.get("rol") or "").strip()
        activo  = (request.POST.get("activo") or "False").strip()

        # --- Validaciones de RUT ---
        if not rut_num.isdigit():
            messages.error(request, "El RUT debe contener solo números (sin puntos ni guion).")
            return redirect("asignar_rol")

        if not (6 <= len(rut_num) <= 8):
            messages.error(request, "El RUT debe tener entre 6 y 8 dígitos.")
            return redirect("asignar_rol")

        if int(rut_num) > 99999999:
            messages.error(request, "El RUT ingresado es inválido.")
            return redirect("asignar_rol")

        if len(digitoV) != 1:
            messages.error(request, "El dígito verificador debe ser un solo carácter (0-9 o K).")
            return redirect("asignar_rol")

        rut_completo = f"{rut_num}-{digitoV}"

        # --- Verificar existencia del usuario ---
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT 1
                  FROM usuarios
                 WHERE rut = %s AND UPPER(digitov) = UPPER(%s)
                 LIMIT 1;
            """, [int(rut_num), digitoV])
            existe_usuario = cursor.fetchone() is not None

        if not existe_usuario:
            messages.error(request, f"El usuario con RUT {rut_completo} no existe.")
            return redirect("asignar_rol")

        # --- Procesar rol ---
        es_sin_rol = (rol_id == "0")
        if not es_sin_rol:
            try:
                rol_id_int = int(rol_id)
            except ValueError:
                messages.error(request, "Rol inválido.")
                return redirect("asignar_rol")

            with connection.cursor() as cursor:
                cursor.execute("SELECT 1 FROM roles WHERE rol_id = %s LIMIT 1;", [rol_id_int])
                if cursor.fetchone() is None:
                    messages.error(request, "El rol seleccionado no existe.")
                    return redirect("asignar_rol")

        estado_ur    = "Activo" if activo == "True" else "Inactivo"
        estado_login = "activo" if activo == "True" else "inactivo"

        # --- Actualizar o eliminar rol ---
        with connection.cursor() as cursor:
            if es_sin_rol:
                cursor.execute(
                    "DELETE FROM usuarios_roles WHERE rut = %s AND digitov = %s;",
                    [int(rut_num), digitoV]
                )
                cursor.execute(
                    "UPDATE login SET estado = %s WHERE rut = %s AND digitov = %s;",
                    ["inactivo", int(rut_num), digitoV]
                )
                messages.info(request, f"Se ha removido el rol del usuario {rut_completo}.")
            else:
                cursor.execute(
                    "SELECT 1 FROM usuarios_roles WHERE rut = %s AND digitov = %s LIMIT 1;",
                    [int(rut_num), digitoV]
                )
                if cursor.fetchone():
                    cursor.execute("""
                        UPDATE usuarios_roles
                           SET rol_id = %s, estado = %s
                         WHERE rut = %s AND digitov = %s;
                    """, [rol_id_int, estado_ur, int(rut_num), digitoV])
                else:
                    cursor.execute("""
                        INSERT INTO usuarios_roles (rut, digitov, rol_id, estado)
                        VALUES (%s, %s, %s, %s);
                    """, [int(rut_num), digitoV, rol_id_int, estado_ur])

                cursor.execute(
                    "UPDATE login SET estado = %s WHERE rut = %s AND digitov = %s;",
                    [estado_login, int(rut_num), digitoV]
                )
                messages.success(request, f"Rol actualizado correctamente para {rut_completo}.")

        return redirect("asignar_rol")

    # =====================================================
    # GET → mostrar listado de usuarios (con búsqueda + paginación)
    # =====================================================

    # 🔍 Búsqueda por RUT o nombre / apellido
    busqueda = request.GET.get("q", "").strip()

    query_base = """
        SELECT 
            u.rut, u.nombre, u.apellidop,
            COALESCE(r.nombre_rol, 'Sin rol') AS nombre_rol,
            COALESCE(ur.estado, 'Inactivo')   AS estado,
            u.digitov
        FROM usuarios u
        LEFT JOIN usuarios_roles ur ON u.rut = ur.rut AND u.digitov = ur.digitov
        LEFT JOIN roles r          ON ur.rol_id = r.rol_id
    """

    parametros = []
    if busqueda:
        query_base += """
            WHERE CAST(u.rut AS TEXT) ILIKE %s
               OR UPPER(u.nombre) LIKE UPPER(%s)
               OR UPPER(u.apellidop) LIKE UPPER(%s)
        """
        parametros = [f"%{busqueda}%", f"%{busqueda}%", f"%{busqueda}%"]

    query_base += " ORDER BY u.nombre;"

    with connection.cursor() as cursor:
        cursor.execute(query_base, parametros)
        usuarios_roles = cursor.fetchall()

    # 📄 Paginación
    paginator = Paginator(usuarios_roles, 5)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    # Renderizado
    return render(request, "accounts/asignar_rol.html", {
        "form": AsignarRolForm(),
        "page_obj": page_obj,
        "current_page": page_obj.number,
        "total_pages": page_obj.paginator.num_pages,
        "busqueda": busqueda,
    })


# ============================================================
# EDITAR PERFIL (solo admin)
# ============================================================

@never_cache
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@role_required("Administrador")
def editar_perfil_admin(request, rut: int, dv: str):
    dv = (dv or "").upper()

    if request.method == "GET":
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT 
                    u.rut, u.digitov, u.nombre, u.apellidop, u.apellidom,
                    u.correo, u.telefono, u.direccion, u.id_comuna,
                    COALESCE(co.nombre, '') AS comuna_nombre,
                    COALESCE(ca.nombre_cargo, '') AS nombre_cargo
                  FROM usuarios u
             LEFT JOIN cuerpo_arbitral c
                    ON c.rut = u.rut AND UPPER(c.digitov) = UPPER(u.digitov)
             LEFT JOIN cargo_arbitral ca ON ca.id_cargo = c.id_cargo
             LEFT JOIN comunas co       ON co.id_comuna = u.id_comuna
                 WHERE u.rut = %s AND UPPER(u.digitov) = UPPER(%s)
                 LIMIT 1;
            """, [rut, dv])
            row = cursor.fetchone()

        if not row:
            messages.error(request, "No se encontró el usuario.")
            return redirect("asignar_rol")

        usuario = {
            "rut": f"{row[0]}-{row[1]}",
            "nombre": row[2], "apellidoP": row[3], "apellidoM": row[4],
            "correo": row[5], "telefono": row[6], "direccion": row[7] or "",
            "id_comuna": row[8], "comuna_nombre": row[9] or "",
            "cargo": row[10] or "No asignado",
        }

        with connection.cursor() as cursor:
            cursor.execute("""SELECT id_comuna, nombre FROM comunas ORDER BY LOWER(nombre);""")
            comunas = cursor.fetchall()

        return render(request, "accounts/editar_perfil_admin.html", {
            "usuario": usuario,
            "comunas": comunas,
            "rut_target": rut,
            "dv_target": dv,
        })

    # POST: admin puede editar más campos
    nombre     = (request.POST.get("nombre") or "").strip()
    apellidop  = (request.POST.get("apellidop") or "").strip()
    apellidom  = (request.POST.get("apellidom") or "").strip()
    correo     = (request.POST.get("correo") or "").strip()
    telefono   = (request.POST.get("telefono") or "").strip() or None
    direccion  = (request.POST.get("direccion") or "").strip() or None
    id_comuna  = (request.POST.get("id_comuna") or "").strip()

    # Validaciones mínimas
    if not nombre or not apellidop:
        messages.error(request, "Nombre y Apellido Paterno son obligatorios.")
        return redirect("editar_perfil_admin", rut=rut, dv=dv)

    id_comuna = int(id_comuna) if id_comuna.isdigit() else None

    with connection.cursor() as cursor:
        cursor.execute("""
            UPDATE usuarios
               SET nombre = %s,
                   apellidop = %s,
                   apellidom = %s,
                   correo = %s,
                   telefono = %s,
                   direccion = %s,
                   id_comuna = %s
             WHERE rut = %s AND UPPER(digitov) = UPPER(%s);
        """, [nombre, apellidop, apellidom, correo, telefono, direccion, id_comuna, rut, dv])

    messages.success(request, f"Perfil de {rut}-{dv} actualizado correctamente.")
    return redirect("asignar_rol")


# ============================================================
# EDITAR CARGO ARBITRAL (solo admin)
# ============================================================

@never_cache
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@role_required("Administrador")
def editar_cargo_arbitral(request):
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT 
                u.rut, 
                u.digitov,
                u.nombre, 
                u.apellidop, 
                COALESCE(ca.nombre_cargo, 'Sin cargo asignado') AS cargo
            FROM usuarios u
            JOIN usuarios_roles ur 
              ON ur.rut = u.rut AND ur.digitov = u.digitov
            JOIN roles r 
              ON ur.rol_id = r.rol_id
       LEFT JOIN cuerpo_arbitral c 
              ON c.rut = u.rut AND c.digitov = u.digitov
       LEFT JOIN cargo_arbitral ca 
              ON ca.id_cargo = c.id_cargo
           WHERE LOWER(r.nombre_rol) = 'arbitro'
        ORDER BY u.nombre;
        """)
        arbitros = cursor.fetchall()

        cursor.execute("""
            SELECT id_cargo, nombre_cargo 
              FROM cargo_arbitral 
          ORDER BY id_cargo;
        """)
        cargos = cursor.fetchall()

    if request.method == "POST":
        rut_completo = request.POST.get("rut")
        id_cargo = request.POST.get("id_cargo")

        if not rut_completo or not id_cargo:
            messages.error(request, "Debes seleccionar un árbitro y un cargo.")
            return redirect("editar_cargo_arbitral")

        try:
            rut_solo, dv = rut_completo.split("-", 1)
            rut_solo = str(int(rut_solo))
            dv = dv.strip().upper()
        except Exception:
            messages.error(request, "RUT inválido.")
            return redirect("editar_cargo_arbitral")

        with connection.cursor() as cursor:
            cursor.execute("""
                DELETE FROM cuerpo_arbitral 
                 WHERE rut = %s AND digitov = %s;
            """, [rut_solo, dv])
            cursor.execute("""
                INSERT INTO cuerpo_arbitral (
                    cantidad_partidos, 
                    cantidad_tarjetas, 
                    funcion_arb, 
                    cursos, 
                    id_partido, 
                    id_cargo, 
                    rut,
                    digitov
                )
                VALUES (0, 0, '', '', NULL, %s, %s, %s);
            """, [id_cargo, rut_solo, dv])

        messages.success(request, "✅ Cargo arbitral actualizado correctamente.")
        return redirect("editar_cargo_arbitral")

    return render(request, "accounts/editar_cargo_arbitral.html", {
        "arbitros": arbitros,
        "cargos": cargos,
    })


# ============================================================
# ASIGNAR PARTIDOS (solo admin)
# ============================================================

@never_cache
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@role_required("Administrador")
def asignar_partidos(request):
    if request.method == "POST":
        partido_id = (request.POST.get("id_partido") or "").strip()

        assign_arbitro   = "assign_arbitro"   in request.POST
        unassign_arbitro = "unassign"         in request.POST   # botón "Quitar Árbitro"
        assign_turno     = "assign_turno"     in request.POST
        unassign_turno   = "unassign_turno"   in request.POST   # botón "Quitar Turno"

        if not (partido_id and partido_id.isdigit()):
            messages.error(request, "ID de partido inválido.")
            return redirect("asignar_partidos")

        partido_id = int(partido_id)

        # ---------------------------
        # Quitar Árbitro
        # ---------------------------
        if unassign_arbitro:
            try:
                with connection.cursor() as cursor:
                    cursor.execute("""
                        UPDATE partidos 
                           SET rut = NULL, digitov = NULL
                         WHERE id_partido = %s;
                    """, [partido_id])
                messages.success(request, f"Asignación de Árbitro eliminada del partido {partido_id}.")
            except Exception as e:
                messages.error(request, f"Error al desasignar árbitro: {e}")
            return redirect("asignar_partidos")

        # ---------------------------
        # Quitar Turno
        # ---------------------------
        if unassign_turno:
            try:
                with connection.cursor() as cursor:
                    cursor.execute("""
                        UPDATE partidos 
                           SET rut_turno = NULL, digitov_turno = NULL
                         WHERE id_partido = %s;
                    """, [partido_id])
                messages.success(request, f"Asignación de Turno eliminada del partido {partido_id}.")
            except Exception as e:
                messages.error(request, f"Error al desasignar turno: {e}")
            return redirect("asignar_partidos")

        # ---------------------------
        # Asignar Árbitro
        # ---------------------------
        if assign_arbitro:
            rut_str = (request.POST.get("rut_arbitro") or "").strip()
            dv      = (request.POST.get("dv_arbitro") or "").strip().upper()

            if not (rut_str.isdigit() and len(dv) == 1 and (dv.isdigit() or dv == "K")):
                messages.error(request, "Datos inválidos para Árbitro. Verifica RUT (solo números) y DV (0-9 o K).")
                return redirect("asignar_partidos")

            rut = int(rut_str)

            # Usuario existe
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT u.nombre, u.apellidop, u.apellidom
                      FROM usuarios u
                     WHERE u.rut = %s AND UPPER(u.digitov) = UPPER(%s);
                """, [rut, dv])
                user = cursor.fetchone()
            if not user:
                messages.error(request, f"El RUT {rut}-{dv} no existe en usuarios.")
                return redirect("asignar_partidos")

            # Rol Árbitro activo
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT 1
                      FROM usuarios_roles ur
                      JOIN roles r ON r.rol_id = ur.rol_id
                     WHERE ur.rut = %s AND UPPER(ur.digitov) = UPPER(%s)
                       AND LOWER(r.nombre_rol) = 'arbitro'
                       AND LOWER(COALESCE(ur.estado,'')) = 'activo'
                     LIMIT 1;
                """, [rut, dv])
                es_arbitro = cursor.fetchone()
            if not es_arbitro:
                messages.error(request, "El usuario no posee rol de Árbitro activo.")
                return redirect("asignar_partidos")

            # Guardar
            try:
                with connection.cursor() as cursor:
                    cursor.execute("""
                        UPDATE partidos
                           SET rut = %s, digitov = UPPER(%s)
                         WHERE id_partido = %s;
                    """, [rut, dv, partido_id])
                nombre_completo = " ".join(filter(None, user))
                messages.success(request, f"Árbitro {nombre_completo} ({rut}-{dv}) asignado al partido {partido_id}.")
            except Exception as e:
                messages.error(request, f"Error al asignar árbitro: {e}")
            return redirect("asignar_partidos")

        # ---------------------------
        # Asignar Turno (jugador O usuario del club de turno)
        # ---------------------------
        if assign_turno:
            rut_str = (request.POST.get("rut_turno") or "").strip()
            dv      = (request.POST.get("dv_turno") or "").strip().upper()

            if not (rut_str.isdigit() and len(dv) == 1 and (dv.isdigit() or dv == "K")):
                messages.error(request, "Datos inválidos para Turno. Verifica RUT (solo números) y DV (0-9 o K).")
                return redirect("asignar_partidos")

            rut = int(rut_str)

            # 1) Verificar que el usuario exista
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT u.nombre, u.apellidop, u.apellidom
                      FROM usuarios u
                     WHERE u.rut = %s AND UPPER(u.digitov) = UPPER(%s);
                """, [rut, dv])
                user = cursor.fetchone()
            if not user:
                messages.error(request, f"El RUT {rut}-{dv} no existe en usuarios.")
                return redirect("asignar_partidos")

            # 2) Verificar que sea MAYOR DE EDAD
            try:
                with connection.cursor() as cursor:
                    cursor.execute("""
                        SELECT 
                            fecha_nacimiento,
                            (DATE_PART('year', AGE(CURRENT_DATE, fecha_nacimiento)) >= 18) AS es_mayor
                      FROM usuarios
                     WHERE rut = %s AND UPPER(digitov) = UPPER(%s)
                     LIMIT 1;
                    """, [rut, dv])
                    row_edad = cursor.fetchone()
            except Exception:
                row_edad = None

            if not row_edad or not row_edad[1]:
                messages.error(request, "El turno debe ser una persona mayor de edad.")
                return redirect("asignar_partidos")

            # 3) Determinar qué club está de turno (equipo libre en esa fecha/serie)
            id_club_turno = _get_club_turno_para_partido(partido_id)
            if not id_club_turno:
                messages.error(request, "No fue posible determinar el club de turno (equipo libre) para este partido.")
                return redirect("asignar_partidos")

            # 4) Verificar que la persona sea de ese club de turno (jugador o usuario)
            pertenece_club_turno = False

            with connection.cursor() as cursor:
                # Como JUGADOR del club
                cursor.execute("""
                    SELECT id_club
                      FROM jugadores
                     WHERE rut_jugador = %s
                       AND UPPER(digitov) = UPPER(%s)
                     LIMIT 1;
                """, [rut, dv])
                fila_jug = cursor.fetchone()
                if fila_jug and fila_jug[0] == id_club_turno:
                    pertenece_club_turno = True

                # Como USUARIO asociado al club (usuarios.id_club)
                if not pertenece_club_turno:
                    cursor.execute("""
                        SELECT id_club
                          FROM usuarios
                         WHERE rut = %s
                           AND UPPER(digitov) = UPPER(%s)
                         LIMIT 1;
                    """, [rut, dv])
                    fila_usu = cursor.fetchone()
                    if fila_usu and fila_usu[0] == id_club_turno:
                        pertenece_club_turno = True

            if not pertenece_club_turno:
                messages.error(
                    request,
                    "La persona indicada para Turno no pertenece al club que hace turno (equipo libre) en esta fecha."
                )
                return redirect("asignar_partidos")

            # 5) Guardar asignación de turno
            try:
                with connection.cursor() as cursor:
                    cursor.execute("""
                        UPDATE partidos
                           SET rut_turno = %s, digitov_turno = UPPER(%s)
                         WHERE id_partido = %s;
                    """, [rut, dv, partido_id])
                nombre_completo = " ".join(filter(None, user))
                messages.success(
                    request,
                    f"Turno {nombre_completo} ({rut}-{dv}) asignado correctamente para el club de turno en el partido {partido_id}."
                )
            except Exception as e:
                messages.error(request, f"Error al asignar turno: {e}")
            return redirect("asignar_partidos")

        messages.warning(request, "Acción no reconocida.")
        return redirect("asignar_partidos")

    # ---------------------------
    # GET: traer partidos + árbitro + turno + club de turno
    # ---------------------------
    partidos_info = []

    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT p.id_partido,
                   p.fecha,
                   p.hora,
                   p.club_local,
                   p.club_visitante,
                   p.rut,           -- Árbitro RUT
                   p.digitov,       -- Árbitro DV
                   p.rut_turno,     -- Turno RUT
                   p.digitov_turno  -- Turno DV
              FROM partidos p
             WHERE p.fecha >= CURRENT_DATE - INTERVAL '30 day'
          ORDER BY p.fecha ASC, p.hora ASC, p.id_partido ASC;
        """)
        rows = cursor.fetchall()

    for (
        id_partido,
        fecha,
        hora,
        club_local,
        club_visitante,
        rut_arbitro,
        dv_arbitro,
        rut_turno,
        dv_turno,
    ) in rows:

        # Nombre completo del árbitro
        nombre_arbitro = None
        if rut_arbitro and dv_arbitro:
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT CONCAT(nombre, ' ', apellidop, ' ', apellidom)
                      FROM usuarios
                     WHERE rut = %s AND UPPER(digitov) = UPPER(%s)
                     LIMIT 1;
                """, [rut_arbitro, dv_arbitro])
                row_arbitro = cursor.fetchone()
                if row_arbitro:
                    nombre_arbitro = row_arbitro[0]

        # Nombre completo del turno
        nombre_turno = None
        if rut_turno and dv_turno:
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT CONCAT(nombre, ' ', apellidop, ' ', apellidom)
                      FROM usuarios
                     WHERE rut = %s AND UPPER(digitov) = UPPER(%s)
                     LIMIT 1;
                """, [rut_turno, dv_turno])
                row_turno = cursor.fetchone()
                if row_turno:
                    nombre_turno = row_turno[0]

        # calcular club de turno (equipo libre)
        id_club_turno = _get_club_turno_para_partido(id_partido)
        club_turno_nombre = None

        if id_club_turno:
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT nombre
                      FROM club
                     WHERE id_club = %s
                     LIMIT 1;
                """, [id_club_turno])
                row_club = cursor.fetchone()
                if row_club:
                    club_turno_nombre = row_club[0]

        partidos_info.append({
            "id": id_partido,
            "fecha": fecha,
            "hora": hora,
            "club_local": club_local,
            "club_visitante": club_visitante,
            "rut_arbitro": rut_arbitro,
            "dv_arbitro": dv_arbitro,
            "nombre_arbitro": nombre_arbitro,
            "rut_turno": rut_turno,
            "dv_turno": dv_turno,
            "nombre_turno": nombre_turno,
            "club_turno_nombre": club_turno_nombre,
        })

    return render(request, "accounts/asignar_partidos.html", {
        "partidos": partidos_info
    })


def _get_club_turno_para_partido(id_partido: int):
    """
    Determina qué club le toca hacer turno para el partido dado, por FECHA (jornada),
    asegurando que NO sea un club que juegue ese día:

    - Usa id_serie y fecha del partido.
    - Obtiene todas las fechas (jornadas) de esa serie ordenadas ascendentemente.
    - Obtiene todos los clubes que participan en la serie (club_serie), ordenados por nombre.
    - Calcula un índice de turno base usando la fecha: idx_fecha % len(clubes).
    - A partir de ese índice, busca un club que NO juegue esa fecha (ni local ni visita).
      Ese será el club de turno (equipo de la jornada).
    """

    # 1) Obtener serie y fecha del partido
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT id_serie, fecha
              FROM partidos
             WHERE id_partido = %s
             LIMIT 1;
        """, [id_partido])
        row = cursor.fetchone()

    if not row:
        return None

    id_serie, fecha = row

    # 2) Todas las fechas (jornadas) de esa serie, ordenadas
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT DISTINCT fecha
              FROM partidos
             WHERE id_serie = %s
          ORDER BY fecha ASC;
        """, [id_serie])
        fechas_rows = cursor.fetchall()

    fechas = [f[0] for f in fechas_rows]

    if not fechas or fecha not in fechas:
        return None

    # Índice de la fecha actual (0, 1, 2, ...) => jornada
    idx_fecha = fechas.index(fecha)

    # 3) Clubes que participan en esa serie, ordenados por nombre
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT cs.id_club
              FROM club_serie cs
              JOIN club c ON c.id_club = cs.id_club
             WHERE cs.id_serie = %s
          ORDER BY LOWER(c.nombre);
        """, [id_serie])
        clubes_rows = cursor.fetchall()

    clubes = [r[0] for r in clubes_rows]

    if not clubes:
        return None

    # 4) Clubes que juegan ese mismo día en la misma serie (local o visita)
    clubes_en_fecha = set()
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT id_club_local, id_club_visitante
              FROM partidos
             WHERE id_serie = %s
               AND fecha    = %s;
        """, [id_serie, fecha])
        for cl, cv in cursor.fetchall():
            if cl:
                clubes_en_fecha.add(cl)
            if cv:
                clubes_en_fecha.add(cv)

    # 5) Seleccionar club de turno a partir de la fecha (rotación),
    #    pero saltando los que juegan ese día.
    n = len(clubes)
    idx_base = idx_fecha % n

    for offset in range(n):
        idx = (idx_base + offset) % n
        candidato = clubes[idx]
        if candidato not in clubes_en_fecha:
            return candidato

    # Si TODOS juegan (caso extremo), no hay club de turno
    return None
# ============================================================
# PERFIL ÁRBITRO
# ============================================================

@never_cache
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def perfil_arbitro(request):
    if not request.session.get("user_rut"):
        return redirect("login")

    try:
        rut, dv = _parse_rut_from_session(request)
    except Exception:
        messages.error(request, "Sesión inválida. Inicie sesión nuevamente.")
        return redirect("login")

    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT 
                u.rut,
                u.digitov,
                u.nombre,
                u.apellidop,
                u.apellidom,
                u.correo,
                u.telefono,
                u.direccion,
                u.id_comuna,
                COALESCE(co.nombre, '') AS comuna_nombre,
                COALESCE(ca.nombre_cargo, '') AS nombre_cargo
            FROM usuarios u
       LEFT JOIN cuerpo_arbitral c
              ON c.rut = u.rut AND UPPER(c.digitov) = UPPER(u.digitov)
       LEFT JOIN cargo_arbitral ca
              ON ca.id_cargo = c.id_cargo
       LEFT JOIN comunas co
              ON co.id_comuna = u.id_comuna
           WHERE u.rut = %s AND UPPER(u.digitov) = UPPER(%s)
           LIMIT 1;
        """, [rut, dv])
        row = cursor.fetchone()

    if not row:
        messages.error(request, "No se encontró información del árbitro.")
        return redirect("login")

    usuario = {
        "rut": f"{row[0]}-{row[1]}",
        "nombre": row[2],
        "apellidoP": row[3],
        "apellidoM": row[4],
        "correo": row[5],
        "telefono": row[6],
        "direccion": row[7] or "",
        "id_comuna": row[8],
        "comuna_nombre": row[9] or "",
        "cargo": row[10] or "No asignado",
    }

    return render(request, "accounts/perfil_arbitro.html", {"usuario": usuario})


# ============================================================
# EDITAR PERFIL
# ============================================================

@never_cache
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def editar_perfil(request):
    if not request.session.get("user_rut"):
        return redirect("login")

    try:
        rut, dv = _parse_rut_from_session(request)
    except Exception:
        messages.error(request, "Sesión inválida. Inicie sesión nuevamente.")
        return redirect("login")

    if request.method == "GET":
        # Datos del usuario + comunas para el select
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT 
                    u.rut, u.digitov, u.nombre, u.apellidop, u.apellidom,
                    u.correo, u.telefono, u.direccion, u.id_comuna,
                    COALESCE(co.nombre, '') AS comuna_nombre,
                    COALESCE(ca.nombre_cargo, '') AS nombre_cargo
                FROM usuarios u
           LEFT JOIN cuerpo_arbitral c
                  ON c.rut = u.rut AND UPPER(c.digitov) = UPPER(u.digitov)
           LEFT JOIN cargo_arbitral ca ON ca.id_cargo = c.id_cargo
           LEFT JOIN comunas co       ON co.id_comuna = u.id_comuna
               WHERE u.rut = %s AND UPPER(u.digitov) = UPPER(%s)
               LIMIT 1;
            """, [rut, dv])
            row = cursor.fetchone()

        if not row:
            messages.error(request, "No se encontró información del árbitro.")
            return redirect("login")

        usuario = {
            "rut": f"{row[0]}-{row[1]}",
            "nombre": row[2], "apellidoP": row[3], "apellidoM": row[4],
            "correo": row[5], "telefono": row[6], "direccion": row[7] or "",
            "id_comuna": row[8], "comuna_nombre": row[9] or "",
            "cargo": row[10] or "No asignado",
        }

        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT id_comuna, nombre
                  FROM comunas
              ORDER BY LOWER(nombre);
            """)
            comunas = cursor.fetchall()

        return render(request, "accounts/editar_perfil.html", {
            "usuario": usuario,
            "comunas": comunas,
        })

    # POST: actualizar campos editables
    correo    = (request.POST.get("correo") or "").strip()
    telefono  = (request.POST.get("telefono") or "").strip()
    direccion = (request.POST.get("direccion") or "").strip()
    id_comuna = (request.POST.get("id_comuna") or "").strip()

    if not correo:
        messages.error(request, "El correo es obligatorio.")
        return redirect("editar_perfil")

    correo_lower = correo.lower()
    if not correo_lower.endswith("@gmail.com"):
        messages.error(request, "El correo debe ser una cuenta de Gmail (termina en @gmail.com).")
        return redirect("editar_perfil")

    telefono  = telefono or None
    direccion = direccion or None
    id_comuna = int(id_comuna) if id_comuna.isdigit() else None

    # Actualizar datos de contacto
    with connection.cursor() as cursor:
        cursor.execute("""
            UPDATE usuarios
               SET correo = %s,
                   telefono = %s,
                   direccion = %s,
                   id_comuna = %s
             WHERE rut = %s AND UPPER(digitov) = UPPER(%s);
        """, [correo, telefono, direccion, id_comuna, rut, dv])

    # =======================================
    # Cambio de contraseña (opcional)
    # =======================================
    actual_pass = (request.POST.get("contrasena_actual") or "").strip()
    nueva_pass1 = (request.POST.get("nueva_contrasena") or "").strip()
    nueva_pass2 = (request.POST.get("confirmar_contrasena") or "").strip()

    cambio_contrasena = False

    # Si el usuario completó algún campo de contraseña, validamos todo
    if actual_pass or nueva_pass1 or nueva_pass2:
        # Todos obligatorios si quiere cambiar
        if not actual_pass or not nueva_pass1 or not nueva_pass2:
            messages.error(request, "Para cambiar la contraseña debe completar los tres campos: actual, nueva y confirmación.")
            return redirect("editar_perfil")

        # Verificar que las nuevas coincidan
        if nueva_pass1 != nueva_pass2:
            messages.error(request, "La nueva contraseña y su confirmación no coinciden.")
            return redirect("editar_perfil")

        # Regla mínima de longitud
        if len(nueva_pass1) < 4:
            messages.error(request, "La nueva contraseña debe tener al menos 4 caracteres.")
            return redirect("editar_perfil")

        # Opcional: evitar que sea igual a la actual
        if nueva_pass1 == actual_pass:
            messages.error(request, "La nueva contraseña no puede ser igual a la actual.")
            return redirect("editar_perfil")

        # Verificar contraseña actual en tabla login
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT contrasena
                  FROM login
                 WHERE rut = %s
                   AND UPPER(digitov) = UPPER(%s)
                   AND estado = 'activo'
                 LIMIT 1;
            """, [rut, dv])
            row = cursor.fetchone()

        if not row:
            messages.error(request, "No se encontró el registro de acceso para este usuario.")
            return redirect("editar_perfil")

        contrasena_db = row[0]

        if contrasena_db != actual_pass:
            messages.error(request, "La contraseña actual no es correcta.")
            return redirect("editar_perfil")

        # Actualizar contraseña
        with connection.cursor() as cursor:
            cursor.execute("""
                UPDATE login
                   SET contrasena = %s
                 WHERE rut = %s
                   AND UPPER(digitov) = UPPER(%s)
                   AND estado = 'activo';
            """, [nueva_pass1, rut, dv])

        cambio_contrasena = True

    # Mensaje final
    if cambio_contrasena:
        messages.success(request, "Perfil y contraseña actualizados correctamente.")
    else:
        messages.success(request, "Perfil actualizado correctamente.")

    return redirect("perfil_arbitro")


# ============================================================
# PARTIDOS ASIGNADOS (árbitro autenticado)
# ============================================================

@never_cache
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def partidos_asignados(request):
    """Lista de partidos asignados al árbitro autenticado, mostrando también estado del acta (si existe)."""
    if not request.session.get("user_rut"):
        return redirect("login")

    try:
        rut, dv = _parse_rut_from_session(request)
    except Exception:
        messages.error(request, "Sesión inválida. Inicia sesión nuevamente.")
        return redirect("login")

    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT DISTINCT ON (p.id_partido)
                p.id_partido,
                p.fecha,
                p.hora,
                COALESCE(p.club_local, '')     AS local,
                COALESCE(p.club_visitante, '') AS visita,
                COALESCE(ca.nombre, '')        AS cancha,
                COALESCE(ea.nombre_estado, p.estado) AS estado_final,
                (a.id_acta IS NOT NULL)        AS tiene_acta
            FROM partidos p
            LEFT JOIN cancha ca ON ca.id_cancha = p.id_cancha
            LEFT JOIN acta_partido a ON a.id_partido = p.id_partido
            LEFT JOIN estado_acta ea ON ea.id_acta = a.id_acta
            WHERE p.rut = %s AND UPPER(p.digitov) = UPPER(%s)
            ORDER BY p.id_partido, a.id_acta DESC;
        """, [rut, dv])
        rows = cursor.fetchall()

    partidos = []
    for r in rows:
        id_partido, fch, hora, local, visita, cancha, estado_final, tiene_acta = r
        partidos.append({
            "id": id_partido,
            "fecha": fch,
            "hora": (hora.strftime("%H:%M") if hora else ""),
            "local": local,
            "visita": visita,
            "cancha": cancha,
            "estado": (estado_final or "").strip(),
            "tiene_acta": bool(tiene_acta),
        })

    # 🧩 DEBUG opcional (ver en consola qué estados tiene)
    print("🧾 Estados de partidos:", [p["estado"] for p in partidos])

    return render(request, "accounts/partidos_asignados.html", {"partidos": partidos})


# ============================================================
# CALENDARIO ÁRBITRO (disponibilidad + partidos)
# ============================================================

@never_cache
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def calendario_arbitro(request):
    if not request.session.get("user_rut"):
        return redirect("login")

    rut_full = request.session["user_rut"]
    try:
        rut, dv = rut_full.split("-")
    except ValueError:
        messages.error(request, "Sesión inválida. Vuelve a iniciar sesión.")
        return redirect("login")
    dv = dv.upper()

    # --- Helpers ---
    def valid_hhmm(s: str) -> bool:
        return bool(re.fullmatch(r"^[0-2]\d:[0-5]\d$", s))

    def overlap_exists(cur, dia, ini, fin):
        """
        Chequea traslape con disponibilidad ACTIVA del mismo día.
        Fuerza comparación de TIME para evitar comparar strings.
        """
        cur.execute("""
            SELECT 1
              FROM disponibilidad_arbitro
             WHERE rut = %s
               AND UPPER(digitov) = UPPER(%s)
               AND dia_semana = %s
               AND activo = TRUE
               AND CAST(%s AS TIME) < franja_fin
               AND CAST(%s AS TIME) > franja_inicio
             LIMIT 1;
        """, [rut, dv, dia, ini, fin])
        return cur.fetchone() is not None

    # --- POST (agregar/eliminar disponibilidad) ---
    if request.method == "POST":
        accion = (request.POST.get("accion") or "").strip().lower()

        if accion == "agregar":
            dia_raw = request.POST.get("dia_semana")
            ini = (request.POST.get("franja_inicio") or "").strip()
            fin = (request.POST.get("franja_fin") or "").strip()

            try:
                dia = int(dia_raw)
            except (TypeError, ValueError):
                dia = -1

            if dia not in range(0, 7):
                messages.error(request, "Selecciona un día válido (0=Dom … 6=Sáb).")
                return redirect("calendario_arbitro")

            if not (ini and fin and valid_hhmm(ini) and valid_hhmm(fin)):
                messages.error(request, "Formato de hora inválido. Usa HH:MM (ej. 09:00).")
                return redirect("calendario_arbitro")

            if ini >= fin:
                messages.error(request, "La hora de inicio debe ser menor que la de término.")
                return redirect("calendario_arbitro")

            try:
                with connection.cursor() as cursor:
                    if overlap_exists(cursor, dia, ini, fin):
                        messages.error(request, "Ya tienes disponibilidad que se solapa en ese día/horario.")
                        return redirect("calendario_arbitro")

                    cursor.execute("""
                        INSERT INTO disponibilidad_arbitro
                            (rut, digitov, dia_semana, franja_inicio, franja_fin, activo)
                        VALUES (%s, UPPER(%s), %s, CAST(%s AS TIME), CAST(%s AS TIME), TRUE);
                    """, [rut, dv, dia, ini, fin])

                messages.success(request, "Disponibilidad agregada.")
            except Exception as e:
                messages.error(request, f"Error al guardar disponibilidad: {e}")
            return redirect("calendario_arbitro")

        elif accion == "eliminar":
            disp_id = request.POST.get("disp_id")
            if not disp_id:
                messages.error(request, "No se indicó el registro a eliminar.")
                return redirect("calendario_arbitro")

            try:
                with connection.cursor() as cursor:
                    cursor.execute("""
                        DELETE FROM disponibilidad_arbitro
                         WHERE id = %s
                           AND rut = %s
                           AND UPPER(digitov) = UPPER(%s);
                    """, [disp_id, rut, dv])

                if cursor.rowcount:
                    messages.success(request, "Disponibilidad eliminada.")
                else:
                    messages.warning(request, "No se encontró el registro o no te pertenece.")
            except Exception as e:
                messages.error(request, f"Error al eliminar: {e}")
            return redirect("calendario_arbitro")

        else:
            messages.warning(request, "Acción no reconocida.")
            return redirect("calendario_arbitro")

    # --- GET: cargar partidos y disponibilidad ---
    try:
        with connection.cursor() as cursor:
            # ORDER BY compatible con MySQL (NULLS al final sin 'NULLS LAST')
            cursor.execute("""
                SELECT p.id_partido, p.fecha, p.hora, p.club_local, p.club_visitante,
                       COALESCE(can.nombre, 'No definida') AS cancha
                  FROM partidos p
             LEFT JOIN cancha can ON can.id_cancha = p.id_cancha
                 WHERE p.rut = %s
                   AND UPPER(p.digitov) = UPPER(%s)
              ORDER BY p.fecha ASC, (p.hora IS NULL) ASC, p.hora ASC, p.id_partido ASC;
            """, [rut, dv])
            mis_partidos = cursor.fetchall()

            cursor.execute("""
                SELECT id, dia_semana, franja_inicio, franja_fin, activo
                  FROM disponibilidad_arbitro
                 WHERE rut = %s
                   AND UPPER(digitov) = UPPER(%s)
              ORDER BY dia_semana ASC, franja_inicio ASC;
            """, [rut, dv])
            disp_raw = cursor.fetchall()
    except Exception as e:
        messages.error(request, f"Error al cargar datos: {e}")
        mis_partidos, disp_raw = [], []

    # Mapeo 0..6 -> nombres de día
    dias_nombres = ["Domingo","Lunes","Martes","Miércoles","Jueves","Viernes","Sábado"]

    # Normaliza la disponibilidad a dicts y formatea hora como HH:MM
    disponibilidad = []
    for _id, dia_idx, ini, fin, activo in disp_raw:
        ini_txt = ini.strftime("%H:%M") if hasattr(ini, "strftime") else str(ini)[:5]
        fin_txt = fin.strftime("%H:%M") if hasattr(fin, "strftime") else str(fin)[:5]
        disponibilidad.append({
            "id": _id,
            "dia_idx": dia_idx,
            "dia_nombre": dias_nombres[dia_idx] if 0 <= dia_idx <= 6 else "—",
            "inicio": ini_txt,
            "fin": fin_txt,
            "activo": bool(activo),
        })

    return render(request, "accounts/calendario_arbitro.html", {
        "partidos": mis_partidos,             # lista de tuplas
        "disponibilidad": disponibilidad,     # lista de dicts
        "dias_select": list(enumerate(dias_nombres)),  # [(0,"Domingo"),...,(6,"Sábado")]
    })


# ============================================================
# PANEL TURNO
# ============================================================

@never_cache
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def panel_turno(request):
    # 1) Seguridad
    if not request.session.get("user_rut"):
        return redirect("login")
    try:
        rut_turno, dv_turno = _parse_rut_from_session(request)
    except Exception:
        messages.error(request, "Sesión inválida. Vuelve a iniciar sesión.")
        return redirect("login")

    rol = (request.session.get("user_rol") or "")
    if "turno" not in rol.lower():
        messages.error(request, "No tienes permisos para acceder al panel del Turno.")
        return redirect("login")

    # 2) Partidos del turno
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT p.id_partido, p.fecha, p.hora,
                   COALESCE(p.club_local,'')     AS local,
                   COALESCE(p.club_visitante,'') AS visita,
                   COALESCE(ca.nombre,'')        AS cancha,
                   p.id_serie,
                   COALESCE(s.nombre,'')         AS serie
              FROM partidos p
         LEFT JOIN cancha ca ON ca.id_cancha = p.id_cancha
         LEFT JOIN serie  s  ON s.id_serie = p.id_serie
             WHERE p.rut_turno = %s
               AND UPPER(p.digitov_turno) = UPPER(%s)
          ORDER BY p.fecha DESC, (p.hora IS NULL) ASC, p.hora DESC, p.id_partido DESC;
        """, [rut_turno, dv_turno])
        partidos_turno = cursor.fetchall()

    # 3) Partido seleccionado
    partido_id_raw = (request.GET.get("partido_id") or request.POST.get("id_partido") or "").strip()
    partido_id = int(partido_id_raw) if partido_id_raw.isdigit() else None

    club_local_txt = club_visita_txt = partido_serie_nombre = ""
    partido_id_serie = None
    id_club_local_sel = id_club_visita_sel = None
    p_fecha = None
    p_hora  = None
    nomina_enviada = False  # flag de estado (si existe columna)

    if partido_id:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT p.id_partido,
                       p.club_local, p.club_visitante,
                       p.id_club_local, p.id_club_visitante,
                       p.id_serie, COALESCE(s.nombre,''),
                       p.fecha, p.hora
                  FROM partidos p
             LEFT JOIN serie s ON s.id_serie = p.id_serie
                 WHERE p.id_partido = %s
                   AND p.rut_turno   = %s
                   AND UPPER(p.digitov_turno) = UPPER(%s)
                 LIMIT 1;
            """, [partido_id, rut_turno, dv_turno])
            row = cursor.fetchone()

        if not row:
            messages.warning(request, "El partido seleccionado no está asignado a tu usuario de turno.")
            partido_id = None
        else:
            (_,
             club_local_txt, club_visita_txt,
             id_club_local_sel, id_club_visita_sel,
             partido_id_serie, partido_serie_nombre,
             p_fecha, p_hora) = row

            # Intentar leer columna opcional nomina_enviada (si existe)
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT COALESCE(nomina_enviada, FALSE) FROM partidos WHERE id_partido=%s", [partido_id])
                    nomina_enviada = bool(cursor.fetchone()[0])
            except Exception:
                nomina_enviada = False

    # 4) Series
    with connection.cursor() as cursor:
        cursor.execute("SELECT id_serie, nombre, COALESCE(categoria,'') FROM serie ORDER BY nombre;")
        series_rows = cursor.fetchall()
    series = [(r[0], r[1]) for r in series_rows]
    serie_info = {r[0]: (r[1], r[2]) for r in series_rows}

    # Helpers edad/serie
    def _calc_edad(fnac):
        if not fnac:
            return None
        hoy = date.today()
        try:
            return hoy.year - fnac.year - ((hoy.month, hoy.day) < (fnac.month, fnac.day))
        except Exception:
            return None

    def _infer_rango_edad(nombre, categoria):
        t = (nombre or categoria or '').lower()
        if '3ra infantil' in t:   return (8, 10)
        if '2da infantil' in t:   return (10, 12)
        if '1ra infantil' in t:   return (12, 14)
        if 'juvenil' in t:        return (15, 18)
        if '3ra adulta' in t:     return (18, None)
        if '2da adulta' in t:     return (18, None)
        if 'honor' in t:          return (18, None)
        if 'super senior' in t:   return (45, None)
        if 'senior' in t:         return (35, None)
        if 'años dor' in t:       return (55, None)
        return (None, None)

    # 5) Nómina del partido -> separada Local / Visita
    nomina_local, nomina_visita = [], []
    if partido_id:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT 
                    j.rut_jugador,
                    UPPER(COALESCE(j.digitov,''))                                   AS dv,
                    TRIM(COALESCE(j.nombre,'') || ' ' || COALESCE(j.apellido,''))    AS nombre,
                    COALESCE(clb.nombre,'')                                          AS club,
                    COALESCE(s.nombre,'')                                            AS serie,
                    COALESCE(jp.camiseta, 0)                                         AS camiseta,
                    j.fecha_nacimiento,
                    COALESCE(jp.id_club, j.id_club)                                  AS id_club_sel,
                    COALESCE(jp.jugo, FALSE)                                         AS jugo,
                    COALESCE(jp.en_cancha, FALSE)                                    AS en_cancha,
                    jp.minuto_entrada,
                    jp.minuto_salida
              FROM jugador_partido jp
              JOIN jugadores j 
                ON j.rut_jugador = jp.rut_jugador
               AND UPPER(COALESCE(j.digitov,'')) = UPPER(COALESCE(jp.digitov,'')) 
         LEFT JOIN club      clb ON clb.id_club = COALESCE(jp.id_club, j.id_club)
         LEFT JOIN serie     s   ON s.id_serie = COALESCE(jp.id_serie, j.id_serie)
             WHERE jp.id_partido = %s
          ORDER BY id_club_sel ASC, jp.camiseta ASC, nombre ASC;
            """, [partido_id])
            rows = cursor.fetchall()

        for (rut_j, dv_j, nombre, club, serie_nom, camiseta, fnac, id_club_sel, jugo, en_cancha, min_in, min_out) in rows:
            edad = _calc_edad(fnac)
            item = {
                "rut": rut_j or "",
                "dv": (dv_j or ""),
                "nombre": nombre or "",
                "club": club or "",
                "serie": serie_nom or "",
                "camiseta": camiseta or "",
                "edad": edad if edad is not None else "",
                "jugo": bool(jugo),
                "en_cancha": bool(en_cancha),
                "min_in": min_in,
                "min_out": min_out,
            }
            if id_club_local_sel and id_club_sel == id_club_local_sel:
                nomina_local.append(item)
            elif id_club_visita_sel and id_club_sel == id_club_visita_sel:
                nomina_visita.append(item)
            else:
                if (club or "").strip().lower() == (club_local_txt or "").strip().lower():
                    nomina_local.append(item)
                else:
                    nomina_visita.append(item)
    
            # ==========================================
    # Sincronizar titulares y en_cancha automáticamente
    # ==========================================
    def marcar_titulares_y_suplentes(nomina, id_partido, id_club):
        """
        Marca los primeros 11 como titulares/en cancha y el resto como suplentes/banca.
        También actualiza la base de datos para mantener la consistencia.
        """
        with connection.cursor() as cursor:
            for i, j in enumerate(nomina):
                es_titular = i < 11
                j["titular"] = es_titular
                j["en_cancha"] = es_titular
                cursor.execute("""
                    UPDATE jugador_partido
                    SET titular = %s, en_cancha = %s
                    WHERE id_partido = %s AND rut_jugador = %s AND UPPER(digitov) = UPPER(%s)
                """, [es_titular, es_titular, id_partido, j["rut"], j["dv"]])
        return nomina

    nomina_local = marcar_titulares_y_suplentes(nomina_local, partido_id, id_club_local_sel)
    nomina_visita = marcar_titulares_y_suplentes(nomina_visita, partido_id, id_club_visita_sel)

    # ==========================================
    # Cambios realizados (sin nuevas tablas)
    # ==========================================
    cambios_local = []
    cambios_visita = []

    if partido_id:
        with connection.cursor() as cursor:
            # Jugadores locales reemplazados (salieron)
            cursor.execute("""
                SELECT TRIM(COALESCE(j.nombre,'') || ' ' || COALESCE(j.apellido,'')) AS nombre, jp.camiseta
                FROM jugador_partido jp
                JOIN jugadores j ON j.rut_jugador = jp.rut_jugador
                WHERE jp.id_partido = %s AND jp.id_club = %s
                  AND jp.jugo = TRUE AND jp.en_cancha = FALSE
                ORDER BY jp.camiseta ASC;
            """, [partido_id, id_club_local_sel])
            salieron_local = cursor.fetchall()

            # Jugadores locales que entraron (en cancha)
            cursor.execute("""
                SELECT TRIM(COALESCE(j.nombre,'') || ' ' || COALESCE(j.apellido,'')) AS nombre, jp.camiseta
                FROM jugador_partido jp
                JOIN jugadores j ON j.rut_jugador = jp.rut_jugador
                WHERE jp.id_partido = %s AND jp.id_club = %s
                  AND jp.jugo = TRUE AND jp.en_cancha = TRUE
                ORDER BY jp.camiseta ASC;
            """, [partido_id, id_club_local_sel])
            entraron_local = cursor.fetchall()

            # Jugadores visita reemplazados (salieron)
            cursor.execute("""
                SELECT TRIM(COALESCE(j.nombre,'') || ' ' || COALESCE(j.apellido,'')) AS nombre, jp.camiseta
                FROM jugador_partido jp
                JOIN jugadores j ON j.rut_jugador = jp.rut_jugador
                WHERE jp.id_partido = %s AND jp.id_club = %s
                  AND jp.jugo = TRUE AND jp.en_cancha = FALSE
                ORDER BY jp.camiseta ASC;
            """, [partido_id, id_club_visita_sel])
            salieron_visita = cursor.fetchall()

            # Jugadores visita que entraron (en cancha)
            cursor.execute("""
                SELECT TRIM(COALESCE(j.nombre,'') || ' ' || COALESCE(j.apellido,'')) AS nombre, jp.camiseta
                FROM jugador_partido jp
                JOIN jugadores j ON j.rut_jugador = jp.rut_jugador
                WHERE jp.id_partido = %s AND jp.id_club = %s
                  AND jp.jugo = TRUE AND jp.en_cancha = TRUE
                ORDER BY jp.camiseta ASC;
            """, [partido_id, id_club_visita_sel])
            entraron_visita = cursor.fetchall()

        # Emparejar visualmente (sin minutos)
        cambios_local = [
            {"entra": e, "sale": s}
            for e, s in zip(entraron_local, salieron_local)
        ]
        cambios_visita = [
            {"entra": e, "sale": s}
            for e, s in zip(entraron_visita, salieron_visita)
        ]


    
    

    ## 5.b) Plantel completo por club (para checklist de jugó)
    plantel_local = plantel_visita = []
    if partido_id and (id_club_local_sel or id_club_visita_sel):
        with connection.cursor() as cursor:
            # Excluir jugadores ya presentes en jugador_partido (nómina oficial)
            cursor.execute("""
                SELECT rut_jugador, UPPER(COALESCE(digitov,'')) AS dv
                FROM jugador_partido
                WHERE id_partido = %s
            """, [partido_id])
            jugadores_en_nomina = {(r[0], r[1]) for r in cursor.fetchall()}

            # Local
            cursor.execute("""
                SELECT j.rut_jugador, UPPER(COALESCE(j.digitov,'')) AS dv,
                    TRIM(COALESCE(j.nombre,'')||' '||COALESCE(j.apellido,'')) AS nombre,
                    COALESCE(j.num_camiseta,0) AS camiseta
                FROM jugadores j
                WHERE j.id_club = %s
            ORDER BY nombre ASC
                LIMIT 200;
            """, [id_club_local_sel])
            plantel_local_full = cursor.fetchall()
            plantel_local = [
                r for r in plantel_local_full
                if (r[0], r[1]) not in jugadores_en_nomina
            ]

            # Visita
            cursor.execute("""
                SELECT j.rut_jugador, UPPER(COALESCE(j.digitov,'')) AS dv,
                    TRIM(COALESCE(j.nombre,'')||' '||COALESCE(j.apellido,'')) AS nombre,
                    COALESCE(j.num_camiseta,0) AS camiseta
                FROM jugadores j
                WHERE j.id_club = %s
            ORDER BY nombre ASC
                LIMIT 200;
            """, [id_club_visita_sel])
            plantel_visita_full = cursor.fetchall()
            plantel_visita = [
                r for r in plantel_visita_full
                if (r[0], r[1]) not in jugadores_en_nomina
            ]

    # 6) POST (agregar / eliminar / marcar jugó / cambios / enviar)
    if request.method == "POST":
        if not partido_id:
            messages.error(request, "Primero selecciona un partido.")
            return redirect("panel_turno")
        
        # Enviar nómina
        if "enviar_nomina" in request.POST:
            try:
                # (Opcional) Validación mínima: 7 por equipo
                with connection.cursor() as cursor:
                    cursor.execute("SELECT id_club_local, id_club_visitante FROM partidos WHERE id_partido=%s", [partido_id])
                    pcl, pcv = cursor.fetchone()
                    cursor.execute("SELECT COUNT(*) FROM jugador_partido WHERE id_partido=%s AND id_club=%s", [partido_id, pcl])
                    cnt_local = cursor.fetchone()[0]
                    cursor.execute("SELECT COUNT(*) FROM jugador_partido WHERE id_partido=%s AND id_club=%s", [partido_id, pcv])
                    cnt_visita = cursor.fetchone()[0]

                if cnt_local < 7 or cnt_visita < 7:
                    messages.error(request, "La nómina debe tener al menos 7 jugadores por equipo para enviarse.")
                    return redirect(f"{reverse('panel_turno')}?partido_id={partido_id}")

                # Intentar marcar bandera en tabla partidos
                try:
                    with connection.cursor() as cursor:
                        cursor.execute("""
                            UPDATE partidos
                               SET nomina_enviada   = TRUE,
                                   nomina_enviada_ts = NOW()
                             WHERE id_partido = %s
                        """, [partido_id])
                    messages.success(request, "Nómina enviada correctamente.")
                    
                    # ============================================================
                    # 📤 Crear acta automática para el Tribunal (junto con la nómina)
                    # ============================================================
                    try:
                        with connection.cursor() as cursor:
                            # Verificar si ya existe un acta previa
                            cursor.execute("""
                                SELECT id_acta FROM acta_partido WHERE id_partido = %s LIMIT 1;
                            """, [partido_id])
                            acta_existente = cursor.fetchone()

                            if not acta_existente:
                                # Obtener información del partido
                                cursor.execute("""
                                    SELECT 
                                        id_partido, fecha, hora, club_local, club_visitante, 
                                        id_torneo, rut_arbitro, digitov_arbitro
                                    FROM partidos
                                    WHERE id_partido = %s
                                    LIMIT 1;
                                """, [partido_id])
                                info = cursor.fetchone()

                                if info:
                                    (pid, fecha_p, hora_p, local, visita, id_torneo,
                                     rut_arbitro, dv_arbitro) = info

                                    # Crear acta básica con estado "Pendiente"
                                    cursor.execute("""
                                        INSERT INTO acta_partido (
                                            id_partido, id_torneo, rut, digitov, fecha_encuentro, resultado, incidentes
                                        )
                                        VALUES (%s,%s,%s,%s,%s,%s,%s)
                                        RETURNING id_acta;
                                    """, [
                                        pid, id_torneo, rut_arbitro, dv_arbitro, fecha_p, 
                                        'Pendiente', 
                                        'Acta generada automáticamente tras el envío de la nómina.'
                                    ])
                                    id_acta = cursor.fetchone()[0]

                                    # Estado inicial
                                    cursor.execute("""
                                        INSERT INTO estado_acta (id_acta, id_estado)
                                        VALUES (
                                            %s,
                                            (SELECT id_estado FROM estado WHERE LOWER(nombre_estado) = LOWER('Pendiente') LIMIT 1)
                                        );
                                    """, [id_acta])

                                    print(f"✅ Acta creada automáticamente para partido {pid} y enviada al Tribunal.")

                            else:
                                print("ℹ️ El acta ya existe, no se crea una nueva.")

                    except Exception as e:
                        print("❌ Error al crear acta automática para el tribunal:", e)

       
                except Exception:
                    messages.success(request, "Nómina enviada (sin columna de estado; se registró sólo el mensaje).")
            except Exception as e:
                messages.error(request, f"No se pudo enviar la nómina: {e}")
            return redirect(f"{reverse('panel_turno')}?partido_id={partido_id}")

        # Eliminar de la nómina
        if "eliminar" in request.POST:
            rut_del = (request.POST.get("rut") or "").strip()
            dv_del  = (request.POST.get("dv")  or "").strip().upper()
            if rut_del.isdigit() and len(dv_del) == 1:
                with connection.cursor() as cursor:
                    cursor.execute("""
                        DELETE FROM jugador_partido jp
                        USING jugadores j
                        WHERE jp.id_partido     = %s
                          AND jp.rut_jugador    = %s
                          AND UPPER(jp.digitov) = UPPER(%s)
                          AND j.rut_jugador     = jp.rut_jugador
                          AND UPPER(COALESCE(j.digitov,'')) = UPPER(jp.digitov);
                    """, [partido_id, int(rut_del), dv_del])
                messages.success(request, "Jugador eliminado de la nómina.")
            else:
                messages.error(request, "RUT/DV inválidos.")
            return redirect(f"{reverse('panel_turno')}?partido_id={partido_id}")

        # Agregar / actualizar jugador en nómina (form manual)
        if "agregar" in request.POST:
            rut_txt   = (request.POST.get("rut") or "").strip()
            dv_txt    = (request.POST.get("dv") or "").strip().upper()
            camiseta  = (request.POST.get("camiseta") or "").strip()
            id_serie  = (request.POST.get("id_serie") or "").strip()

            if not (rut_txt.isdigit() and camiseta.isdigit() and id_serie.isdigit()
                    and len(dv_txt) == 1 and re.match(r'^[0-9K]$', dv_txt)):
                messages.error(request, "Datos inválidos. Revisa RUT, DV, Serie y Camiseta.")
                return redirect(f"{reverse('panel_turno')}?partido_id={partido_id}")

            rut_jugador = int(rut_txt)
            camiseta = int(camiseta)
            id_serie_sel = int(id_serie)

            # ids clubes del partido
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT id_club_local, id_club_visitante
                    FROM partidos
                    WHERE id_partido = %s
                """, [partido_id])
                pcl, pcv = cursor.fetchone()

            # jugador por RUT/DV
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT j.rut_jugador, j.id_club, j.fecha_nacimiento, UPPER(COALESCE(j.digitov,'')) AS dv
                    FROM jugadores j
                    WHERE j.rut_jugador = %s
                    AND UPPER(COALESCE(j.digitov,'')) = UPPER(%s)
                    LIMIT 1;
                """, [rut_jugador, dv_txt])
                jrow = cursor.fetchone()

            if not jrow:
                messages.error(request, "El jugador no existe con ese RUT/DV.")
                return redirect(f"{reverse('panel_turno')}?partido_id={partido_id}")

            _, id_club_j, fnac, dv_j = jrow

            # Validar club del jugador vs partido
            if id_club_j not in (pcl, pcv):
                messages.error(request, "El jugador no pertenece a un club que dispute este partido.")
                return redirect(f"{reverse('panel_turno')}?partido_id={partido_id}")

            # Validar edad vs serie
            nombre_serie, cat_serie = serie_info.get(id_serie_sel, ("",""))
            min_e, max_e = _infer_rango_edad(nombre_serie, cat_serie)
            edad = _calc_edad(fnac)
            if edad is not None and ((min_e is not None and edad < min_e) or (max_e is not None and edad > max_e)):
                messages.error(request, f"El jugador no cumple la edad para la serie {nombre_serie}.")
                return redirect(f"{reverse('panel_turno')}?partido_id={partido_id}")

            # Pre-check colisión de camiseta
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT COALESCE(j.nombre,'')||' '||COALESCE(j.apellido,'') AS nom
                    FROM jugador_partido jp
                    JOIN jugadores j ON j.rut_jugador = jp.rut_jugador
                    WHERE jp.id_partido = %s
                    AND jp.id_club    = %s
                    AND jp.camiseta   = %s
                    AND NOT (jp.rut_jugador = %s AND UPPER(jp.digitov) = UPPER(%s))
                    LIMIT 1;
                """, [partido_id, id_club_j, camiseta, rut_jugador, dv_j])
                dup = cursor.fetchone()
            if dup:
                messages.error(request, f"La camiseta #{camiseta} ya está asignada a {dup[0]} en este club para este partido.")
                return redirect(f"{reverse('panel_turno')}?partido_id={partido_id}")

            # Determinar si será TITULAR o SUPLENTE (según cantidad actual)
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT COUNT(*) 
                    FROM jugador_partido 
                    WHERE id_partido = %s AND id_club = %s AND titular = TRUE
                """, [partido_id, id_club_j])
                total_titulares = cursor.fetchone()[0]

            es_titular = total_titulares < 11  # Primeros 11 = titulares

            # Upsert con titularidad
            try:
                with transaction.atomic():
                    with connection.cursor() as cursor:
                        cursor.execute("""
                            INSERT INTO jugador_partido 
                                (id_partido, rut_jugador, digitov, camiseta, id_club, id_serie, jugo, en_cancha, titular)
                            VALUES (%s, %s, %s, %s, %s, %s, TRUE, TRUE, %s)
                            ON CONFLICT (id_partido, rut_jugador, digitov) DO UPDATE
                            SET camiseta = EXCLUDED.camiseta,
                                id_club  = EXCLUDED.id_club,
                                id_serie = EXCLUDED.id_serie,
                                jugo     = TRUE,
                                en_cancha= TRUE,
                                titular  = EXCLUDED.titular;
                        """, [partido_id, rut_jugador, dv_j, camiseta, id_club_j, id_serie_sel, es_titular])
                if es_titular:
                    messages.success(request, f"Jugador agregado como TITULAR ({total_titulares + 1}/11).")
                else:
                    messages.info(request, "Jugador agregado como SUPLENTE (banca).")
            except IntegrityError:
                messages.error(request, f"La camiseta #{camiseta} ya está asignada en este club para este partido.")
            except Exception as e:
                messages.error(request, f"Error al agregar: {e}")

            return redirect(f"{reverse('panel_turno')}?partido_id={partido_id}")


        # Marcar "jugó" desde plantel (Seleccionar -> inserta si no existe, pide camiseta)
        if "plantel_add" in request.POST:
            side      = (request.POST.get("side") or "").strip()  # local/visita
            rut_txt   = (request.POST.get("rut") or "").strip()
            dv_txt    = (request.POST.get("dv") or "").strip().upper()
            camiseta  = (request.POST.get("camiseta") or "").strip()

            if side not in ("local","visita") or not rut_txt.isdigit() or len(dv_txt) != 1 or not camiseta.isdigit():
                messages.error(request, "Datos inválidos del plantel. Ingresa la camiseta.")
                return redirect(f"{reverse('panel_turno')}?partido_id={partido_id}")

            rut_j = int(rut_txt)
            cam_i = int(camiseta)

            with connection.cursor() as cursor:
                cursor.execute("SELECT id_club_local, id_club_visitante, id_serie FROM partidos WHERE id_partido=%s", [partido_id])
                pcl, pcv, serie_p = cursor.fetchone()
            id_club_side = pcl if side == "local" else pcv

            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT j.rut_jugador, UPPER(COALESCE(j.digitov,'')) AS dv, j.id_club
                    FROM jugadores j
                    WHERE j.rut_jugador = %s
                    AND UPPER(COALESCE(j.digitov,'')) = UPPER(%s)
                    LIMIT 1;
                """, [rut_j, dv_txt])
                jrow = cursor.fetchone()

            if not jrow:
                messages.error(request, "Jugador no existe con ese RUT/DV.")
                return redirect(f"{reverse('panel_turno')}?partido_id={partido_id}")

            _, dv_db, id_club_j = jrow
            if id_club_j != id_club_side:
                messages.error(request, "Jugador no pertenece al club seleccionado.")
                return redirect(f"{reverse('panel_turno')}?partido_id={partido_id}")

            # Pre-check colisión de camiseta
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT COALESCE(j.nombre,'')||' '||COALESCE(j.apellido,'') AS nom
                    FROM jugador_partido jp
                    JOIN jugadores j ON j.rut_jugador = jp.rut_jugador
                    WHERE jp.id_partido = %s
                    AND jp.id_club    = %s
                    AND jp.camiseta   = %s
                    AND NOT (jp.rut_jugador = %s AND UPPER(jp.digitov) = UPPER(%s))
                    LIMIT 1;
                """, [partido_id, id_club_side, cam_i, rut_j, dv_db])
                dup = cursor.fetchone()
            if dup:
                messages.error(request, f"La camiseta #{cam_i} ya está asignada a {dup[0]} en este club para este partido.")
                return redirect(f"{reverse('panel_turno')}?partido_id={partido_id}")

            # Contar titulares actuales
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT COUNT(*) 
                    FROM jugador_partido 
                    WHERE id_partido = %s AND id_club = %s AND titular = TRUE
                """, [partido_id, id_club_side])
                total_titulares = cursor.fetchone()[0]

            es_titular = total_titulares < 11  # Primeros 11 son titulares

            # Upsert: marca jugó y en_cancha TRUE + titularidad
            try:
                with transaction.atomic():
                    with connection.cursor() as cursor:
                        cursor.execute("""
                            INSERT INTO jugador_partido 
                                (id_partido, rut_jugador, digitov, camiseta, id_club, id_serie, jugo, en_cancha, titular)
                            VALUES (%s, %s, %s, %s, %s, %s, TRUE, TRUE, %s)
                            ON CONFLICT (id_partido, rut_jugador, digitov) DO UPDATE
                            SET jugo     = TRUE,
                                en_cancha= TRUE,
                                camiseta  = EXCLUDED.camiseta,
                                id_club   = EXCLUDED.id_club,
                                id_serie  = COALESCE(EXCLUDED.id_serie, jugador_partido.id_serie),
                                titular   = EXCLUDED.titular;
                        """, [partido_id, rut_j, dv_db, cam_i, id_club_side, serie_p, es_titular])
                if es_titular:
                    messages.success(request, f"Jugador agregado como TITULAR ({total_titulares + 1}/11).")
                else:
                    messages.info(request, "Jugador agregado como SUPLENTE (banca).")
            except IntegrityError:
                messages.error(request, f"La camiseta #{cam_i} ya está asignada en este club para este partido.")
            except Exception as e:
                messages.error(request, f"Error al agregar desde plantel: {e}")
                

        # Registrar CAMBIO (SALE / ENTRA)
        if "registrar_cambio" in request.POST:
            side       = (request.POST.get("side") or "").strip()
            sale_rut   = (request.POST.get("sale_rut") or "").strip()
            sale_dv    = (request.POST.get("sale_dv") or "").strip().upper()
            entra_rut  = (request.POST.get("entra_rut") or "").strip()
            entra_dv   = (request.POST.get("entra_dv") or "").strip().upper()
            sale_cam   = (request.POST.get("sale_camiseta") or "").strip()
            entra_cam  = (request.POST.get("entra_camiseta") or "").strip()

            # Validaciones básicas
            if side not in ("local", "visita") or not (sale_rut.isdigit() and entra_rut.isdigit()):
                messages.error(request, "Datos de cambio inválidos.")
                return redirect(f"{reverse('panel_turno')}?partido_id={partido_id}")

            sale_rut_i  = int(sale_rut)
            entra_rut_i = int(entra_rut)
            sale_cam_i  = int(sale_cam)
            entra_cam_i = int(entra_cam)

            # Obtener clubes del partido
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT id_club_local, id_club_visitante, 
                        COALESCE(club_local,''), COALESCE(club_visitante,'')
                    FROM partidos WHERE id_partido = %s
                """, [partido_id])
                pcl, pcv, local_txt, visita_txt = cursor.fetchone()

            id_club_side = pcl if side == "local" else pcv

            # Verificar jugadores
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT j.rut_jugador, UPPER(COALESCE(j.digitov,'')) AS dv, 
                        TRIM(COALESCE(j.nombre,'') || ' ' || COALESCE(j.apellido,'')) AS nombre,
                        jp.camiseta, jp.id_club, jp.en_cancha, jp.titular
                    FROM jugadores j
                    JOIN jugador_partido jp
                        ON jp.rut_jugador = j.rut_jugador
                    AND UPPER(COALESCE(j.digitov,'')) = UPPER(jp.digitov)
                    WHERE jp.id_partido = %s
                    AND j.rut_jugador IN (%s, %s)
                """.replace("%s, %s", "%s, %s"), [partido_id, sale_rut_i, entra_rut_i])
                jug_rows = cursor.fetchall()

            if not jug_rows or len(jug_rows) < 2:
                messages.error(request, "Ambos jugadores deben estar en la nómina del partido.")
                return redirect(f"{reverse('panel_turno')}?partido_id={partido_id}")

            j_by_rut = {r[0]: r for r in jug_rows}
            js = j_by_rut.get(sale_rut_i)
            je = j_by_rut.get(entra_rut_i)

            _, js_dv, js_nom, js_cam, js_club, js_en_cancha, js_titular = js
            _, je_dv, je_nom, je_cam, je_club, je_en_cancha, je_titular = je

            # Validaciones lógicas
            if js_club != id_club_side or je_club != id_club_side:
                messages.error(request, "Los jugadores no pertenecen al mismo equipo.")
                return redirect(f"{reverse('panel_turno')}?partido_id={partido_id}")

            if js_cam != sale_cam_i or je_cam != entra_cam_i:
                messages.error(request, "Las camisetas no coinciden con la nómina.")
                return redirect(f"{reverse('panel_turno')}?partido_id={partido_id}")

            if not js_en_cancha:
                messages.error(request, f"{js_nom} no está actualmente en cancha.")
                return redirect(f"{reverse('panel_turno')}?partido_id={partido_id}")

            if je_en_cancha:
                messages.error(request, f"{je_nom} ya está en cancha, no puede ingresar nuevamente.")
                return redirect(f"{reverse('panel_turno')}?partido_id={partido_id}")

            # Aplicar cambio simple (sin minutos)
            with connection.cursor() as cursor:
                # SALE
                cursor.execute("""
                    UPDATE jugador_partido
                    SET en_cancha = FALSE, jugo = TRUE
                    WHERE id_partido = %s
                    AND rut_jugador = %s
                    AND UPPER(digitov) = UPPER(%s)
                    AND id_club = %s
                    AND camiseta = %s
                """, [partido_id, sale_rut_i, sale_dv, id_club_side, sale_cam_i])

                # ENTRA
                cursor.execute("""
                    UPDATE jugador_partido
                    SET en_cancha = TRUE, jugo = TRUE
                    WHERE id_partido = %s
                    AND rut_jugador = %s
                    AND UPPER(digitov) = UPPER(%s)
                    AND id_club = %s
                    AND camiseta = %s
                """, [partido_id, entra_rut_i, entra_dv, id_club_side, entra_cam_i])

            messages.success(request, f"✅ Cambio realizado correctamente: {je_nom} entra ↔ {js_nom} sale.")
            return redirect(f"{reverse('panel_turno')}?partido_id={partido_id}")


        
        # ============================================================
        # 🔹 NUEVO: Agregar jugadores de forma masiva por club
        # ============================================================
        if "plantel_add_masivo" in request.POST:
            side = (request.POST.get("side") or "").strip()
            if side not in ("local", "visita"):
                messages.error(request, "Equipo inválido para agregar jugadores.")
                return redirect(f"{reverse('panel_turno')}?partido_id={partido_id}")

            with connection.cursor() as cursor:
                cursor.execute("SELECT id_club_local, id_club_visitante, id_serie FROM partidos WHERE id_partido=%s", [partido_id])
                pcl, pcv, serie_p = cursor.fetchone()
            id_club_side = pcl if side == "local" else pcv

            agregados = 0
            for key, val in request.POST.items():
                if key.startswith("camiseta_") and val.strip().isdigit():
                    rut = key.split("_")[1]
                    dv = (request.POST.get(f"dv_{rut}") or "").upper().strip()
                    if not (rut.isdigit() and len(dv) == 1):
                        continue

                    camiseta = int(val)
                    rut_i = int(rut)

                    with connection.cursor() as cursor:
                        cursor.execute("""
                            INSERT INTO jugador_partido (id_partido, rut_jugador, digitov, camiseta, id_club, id_serie, jugo, en_cancha)
                            VALUES (%s, %s, %s, %s, %s, %s, TRUE, TRUE)
                            ON CONFLICT (id_partido, rut_jugador, digitov) DO UPDATE
                            SET camiseta = EXCLUDED.camiseta,
                                jugo = TRUE,
                                en_cancha = TRUE;
                        """, [partido_id, rut_i, dv, camiseta, id_club_side, serie_p])
                        agregados += 1

            messages.success(request, f"{agregados} jugadores agregados correctamente desde el plantel {side}.")
            return redirect(f"{reverse('panel_turno')}?partido_id={partido_id}")
        

        # ============================================================
        # 🔄 REGISTRAR CAMBIO (SALE / ENTRA) — sin minutos ni tablas nuevas
        # ============================================================
        if "registrar_cambio" in request.POST:
            side       = (request.POST.get("side") or "").strip()
            sale_rut   = (request.POST.get("sale_rut") or "").strip()
            sale_dv    = (request.POST.get("sale_dv") or "").strip().upper()
            entra_rut  = (request.POST.get("entra_rut") or "").strip()
            entra_dv   = (request.POST.get("entra_dv") or "").strip().upper()
            sale_cam   = (request.POST.get("sale_camiseta") or "").strip()
            entra_cam  = (request.POST.get("entra_camiseta") or "").strip()

            # ✅ Validación básica
            if side not in ("local", "visita") or not (sale_rut.isdigit() and entra_rut.isdigit()):
                messages.error(request, "Datos de cambio inválidos.")
                return redirect(f"{reverse('panel_turno')}?partido_id={partido_id}")

            if not (len(sale_dv) == 1 and len(entra_dv) == 1 and sale_cam.isdigit() and entra_cam.isdigit()):
                messages.error(request, "DV y camisetas deben ser válidos.")
                return redirect(f"{reverse('panel_turno')}?partido_id={partido_id}")

            sale_rut_i  = int(sale_rut)
            entra_rut_i = int(entra_rut)
            sale_cam_i  = int(sale_cam)
            entra_cam_i = int(entra_cam)

            # 🔹 Obtener clubes del partido
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT id_club_local, id_club_visitante, COALESCE(club_local,''), COALESCE(club_visitante,'')
                    FROM partidos
                    WHERE id_partido = %s
                """, [partido_id])
                pcl, pcv, local_txt, visita_txt = cursor.fetchone()

            id_club_side = pcl if side == "local" else pcv

            # 🔹 Traer jugadores desde la nómina
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT j.rut_jugador, UPPER(COALESCE(j.digitov,'')) AS dv,
                        TRIM(COALESCE(j.nombre,'')||' '||COALESCE(j.apellido,'')) AS nombre,
                        jp.camiseta, jp.id_club, jp.en_cancha, jp.jugo
                    FROM jugadores j
                    JOIN jugador_partido jp
                        ON jp.rut_jugador = j.rut_jugador
                    AND UPPER(COALESCE(j.digitov,'')) = UPPER(jp.digitov)
                    WHERE jp.id_partido = %s
                    AND j.rut_jugador IN (%s, %s)
                """.replace("%s, %s", "%s, %s"), [partido_id, sale_rut_i, entra_rut_i])
                jug_rows = cursor.fetchall()

            j_by_rut = {r[0]: r for r in jug_rows}
            js = j_by_rut.get(sale_rut_i)
            je = j_by_rut.get(entra_rut_i)

            if not js or not je:
                messages.error(request, "Ambos jugadores deben estar en la nómina del partido.")
                return redirect(f"{reverse('panel_turno')}?partido_id={partido_id}")

            _, js_dv, js_nom, js_cam, js_club, js_en_cancha, js_jugo = js
            _, je_dv, je_nom, je_cam, je_club, je_en_cancha, je_jugo = je

            # 🔹 Validaciones de club y camiseta
            if js_club != id_club_side or je_club != id_club_side:
                messages.error(request, "Los jugadores deben pertenecer al mismo equipo.")
                return redirect(f"{reverse('panel_turno')}?partido_id={partido_id}")

            if js_cam != sale_cam_i or je_cam != entra_cam_i:
                messages.error(request, "Los números de camiseta no coinciden con la nómina.")
                return redirect(f"{reverse('panel_turno')}?partido_id={partido_id}")

            # 🔹 Validar si el jugador que sale ya está fuera
            if not js_en_cancha:
                messages.warning(request, f"El jugador #{sale_cam_i} ya está fuera del campo.")
                return redirect(f"{reverse('panel_turno')}?partido_id={partido_id}")

            # 🔹 Validar si el jugador que entra ya está dentro
            if je_en_cancha:
                messages.warning(request, f"El jugador #{entra_cam_i} ya está dentro del campo.")
                return redirect(f"{reverse('panel_turno')}?partido_id={partido_id}")

            # 🔹 Contar cambios realizados (jugadores que ya salieron del campo)
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT COUNT(*) 
                    FROM jugador_partido
                    WHERE id_partido = %s AND id_club = %s AND en_cancha = FALSE
                    AND minuto_salida IS NOT NULL
                """, [partido_id, id_club_side])
                total_cambios = cursor.fetchone()[0]

            if total_cambios >= 5:
                messages.warning(request, f"⚠️ Límite de cambios alcanzado para {side.upper()} (5 por equipo).")
                return redirect(f"{reverse('panel_turno')}?partido_id={partido_id}")

            # 🔹 Registrar cambio (sin minutos automáticos)
            with connection.cursor() as cursor:
                # Jugador que SALE
                cursor.execute("""
                    UPDATE jugador_partido
                    SET en_cancha = FALSE,
                        jugo = TRUE,
                        minuto_salida = 0
                    WHERE id_partido = %s
                    AND rut_jugador = %s
                    AND UPPER(digitov) = UPPER(%s)
                    AND id_club = %s
                    AND camiseta = %s;
                """, [partido_id, sale_rut_i, sale_dv, id_club_side, sale_cam_i])

                # Jugador que ENTRA
                cursor.execute("""
                    UPDATE jugador_partido
                    SET en_cancha = TRUE,
                        jugo = TRUE,
                        minuto_entrada = 0
                    WHERE id_partido = %s
                    AND rut_jugador = %s
                    AND UPPER(digitov) = UPPER(%s)
                    AND id_club = %s
                    AND camiseta = %s;
                """, [partido_id, entra_rut_i, entra_dv, id_club_side, entra_cam_i])

            messages.success(request, f"✅ Cambio registrado correctamente: entra #{entra_cam_i} ({je_nom}), sale #{sale_cam_i} ({js_nom}).")
            return redirect(f"{reverse('panel_turno')}?partido_id={partido_id}")

        # ------------------------------------------------------------
        # Guardar borrador o cerrar nómina
        # ------------------------------------------------------------
        if "guardar_borrador" in request.POST:
            messages.info(request, "📝 Borrador guardado correctamente.")
            return redirect(f"{reverse('panel_turno')}?partido_id={partido_id}")

        if "cerrar_nomina" in request.POST:
            messages.success(request, "✅ Nómina cerrada correctamente.")
            return redirect(f"{reverse('panel_turno')}?partido_id={partido_id}")


    # 7) Render
    ctx = {
        "partidos_turno": partidos_turno,
        "partido_id": partido_id,
        "partido_id_serie": partido_id_serie,
        "partido_serie_nombre": partido_serie_nombre,
        "club_local_txt": club_local_txt,
        "club_visita_txt": club_visita_txt,
        "series": series,
        "nomina_local": nomina_local,
        "nomina_visita": nomina_visita,
        "plantel_local": plantel_local,
        "plantel_visita": plantel_visita,
        "p_tiene_hora": bool(p_hora),
        "nomina_enviada": nomina_enviada,
        "cambios_local": cambios_local,
        "cambios_visita": cambios_visita,
        
    }
    return render(request, "accounts/panel_turno.html", ctx)



# ============================================================
# TRIBUNAL DE DISCIPLINA
# ============================================================
@never_cache
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@role_required("Tribunal de Disciplina")
def panel_tribunal(request):
    """Panel principal del Tribunal de Disciplina."""
    if not request.session.get("user_rut"):
        return redirect("login")

    user_nombre = request.session.get("user_nombre", "Usuario")

    # ============================================================
    # 🔹 Si el tribunal actualiza una acta
    # ============================================================
    if request.method == "POST":
        id_acta       = request.POST.get("id_acta")
        nuevo_estado  = request.POST.get("estado")
        observacion   = (request.POST.get("observacion") or "").strip()

        # Campos opcionales para sanción dictada por el Tribunal
        id_jugador_raw   = (request.POST.get("id_jugador") or "").strip()
        id_club_raw      = (request.POST.get("id_club") or "").strip()
        tipo_sancion     = (request.POST.get("tipo_sancion") or "").strip()
        motivo_sancion_f = (request.POST.get("motivo_sancion") or "").strip()

        # Normalizar a enteros / None
        id_jugador = int(id_jugador_raw) if id_jugador_raw.isdigit() else None
        id_club    = int(id_club_raw)    if id_club_raw.isdigit()    else None

        if id_acta and nuevo_estado:
            with connection.cursor() as cursor:
                # ============================================================
                # 🔄 Actualización del estado del acta
                # ============================================================
                cursor.execute("""
                    UPDATE estado_acta
                       SET nombre_estado = %s,
                           descripcion   = %s
                     WHERE id_acta       = %s;
                """, [
                    nuevo_estado,
                    observacion or f"Estado actualizado a '{nuevo_estado}' por el Tribunal de Disciplina.",
                    id_acta
                ])

                # ============================================================
                # ✅ Si se APRUEBA, recalcular posiciones y (opcionalmente) crear sanción
                # ============================================================
                if nuevo_estado == "Aprobada":
                    # Obtenemos torneo y datos del partido para recalcular tabla
                    cursor.execute("""
                        SELECT 
                            a.id_torneo,
                            p.id_serie,
                            p.id_club_local,
                            p.id_club_visitante
                        FROM acta_partido a
                        JOIN partidos p ON p.id_partido = a.id_partido
                       WHERE a.id_acta = %s
                       LIMIT 1;
                    """, [id_acta])
                    row = cursor.fetchone()

                    torneo_id      = None
                    id_serie       = None
                    id_club_local  = None
                    id_club_visita = None

                    if row:
                        torneo_id, id_serie, id_club_local, id_club_visita = row
                    else:
                        torneo_id = _get_default_torneo_id()

                    # Recalcular tabla de posiciones si tenemos torneo
                    if torneo_id:
                        _recalcular_tabla_torneo(torneo_id)

                    # --------------------------------------------------------
                    # 🟥 Crear sanción SOLO si el Tribunal ingresó datos
                    # --------------------------------------------------------
                    # Consideramos "hay sanción" si al menos escribió tipo o motivo,
                    # o indicó jugador/club.
                    hay_datos_sancion = any([
                        tipo_sancion,
                        motivo_sancion_f,
                        id_jugador is not None,
                        id_club is not None,
                    ])

                    if id_serie and hay_datos_sancion:
                        # Fallbacks por si no completan todo
                        tipo_final = tipo_sancion or "Sanción Tribunal"
                        motivo_final = (
                            motivo_sancion_f
                            or observacion
                            or f"Sanción dictada por el Tribunal al aprobar el acta #{id_acta}."
                        )

                        # Si no especificaron club, usamos por defecto el local (puedes cambiar a visita)
                        if id_club is None:
                            id_club = id_club_local

                        # 👇 Ajusta este INSERT a la estructura real de tu tabla `sanciones`
                        cursor.execute("""
                            INSERT INTO sanciones (
                                id_jugador,
                                id_serie,
                                id_club,
                                tipo,
                                motivo,
                                fecha_inc
                            )
                            VALUES (%s, %s, %s, %s, %s, CURRENT_DATE);
                        """, [
                            id_jugador,   # puede ser None si no se indica jugador específico
                            id_serie,
                            id_club,
                            tipo_final,
                            motivo_final,
                        ])

                # ❌ Si se RECHAZA, devolverla al árbitro (sin sanción)
                elif nuevo_estado == "Rechazada":
                    cursor.execute("""
                        UPDATE acta_partido
                           SET fecha_devolucion     = NOW(),
                               observacion_tribunal = %s
                         WHERE id_acta             = %s;
                    """, [
                        observacion or "El tribunal ha rechazado el acta. Debe ser corregida y reenviada por el árbitro.",
                        id_acta
                    ])

            # ✅ Mensaje visible solo dentro del panel
            request.session["mensaje_acta"] = f"✅ Acta #{id_acta} actualizada a '{nuevo_estado}'."
            return redirect("panel_tribunal")

    # ============================================================
    # 🔹 Mensaje de bienvenida (solo visible en panel)
    # ============================================================
    mensaje_bienvenida = None
    if not request.session.get("bienvenida_mostrada", False):
        mensaje_bienvenida = f"Bienvenido {user_nombre}"
        request.session["bienvenida_mostrada"] = True

    mensaje = request.session.pop("mensaje_acta", None)

    # ============================================================
    # 🔹 Consultas separadas
    # ============================================================
    with connection.cursor() as cursor:
        # Actas pendientes o en revisión
        cursor.execute("""
            SELECT 
                a.id_acta,
                p.club_local,
                p.club_visitante,
                p.fecha,
                COALESCE(a.incidentes, 'Sin incidentes reportados'),
                COALESCE(ea.nombre_estado, 'Pendiente')
            FROM acta_partido a
            JOIN partidos p   ON a.id_partido = p.id_partido
            JOIN estado_acta ea ON ea.id_acta = a.id_acta
           WHERE ea.nombre_estado IN ('Pendiente', 'En revisión')
           ORDER BY p.fecha DESC;
        """)
        actas_recibidas = cursor.fetchall()

        # Actas revisadas
        cursor.execute("""
            SELECT 
                a.id_acta,
                p.club_local,
                p.club_visitante,
                p.fecha,
                COALESCE(a.incidentes, 'Sin incidentes reportados'),
                COALESCE(ea.nombre_estado, 'Pendiente')
            FROM acta_partido a
            JOIN partidos p   ON a.id_partido = p.id_partido
            JOIN estado_acta ea ON ea.id_acta = a.id_acta
           WHERE ea.nombre_estado IN ('Aprobada', 'Rechazada')
           ORDER BY p.fecha DESC;
        """)
        actas_revisadas = cursor.fetchall()

    contexto = {
        "user_nombre":        user_nombre,
        "actas_recibidas":    actas_recibidas,
        "actas_revisadas":    actas_revisadas,
        "mensaje":            mensaje,
        "mensaje_bienvenida": mensaje_bienvenida,
    }

    return render(request, "accounts/tribunal.html", contexto)

# ============================================================
# 🧾 VER DETALLE DE ACTA (para el Tribunal)
# ============================================================
@never_cache
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@role_required("Tribunal de Disciplina")
def ver_acta(request, id_acta):
    """Muestra el detalle de una acta, incluyendo nómina de jugadores."""
    if not request.session.get("user_rut"):
        return redirect("login")

    # Datos del acta + partido
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT 
                a.id_acta, a.goles_local, a.goles_visita, a.incidentes,
                a.tarjetas_amarillas, a.tarjetas_rojas,
                p.id_partido, p.club_local, p.club_visitante, 
                p.fecha, p.hora, COALESCE(ca.nombre,'Sin cancha'),
                COALESCE(ea.nombre_estado,'Pendiente')
            FROM acta_partido a
            JOIN partidos p ON a.id_partido = p.id_partido
            LEFT JOIN cancha ca ON ca.id_cancha = p.id_cancha
            LEFT JOIN estado_acta ea ON ea.id_acta = a.id_acta
            WHERE a.id_acta = %s
            LIMIT 1;
        """, [id_acta])
        info = cursor.fetchone()

    if not info:
        messages.error(request, "❌ No se encontró el acta solicitada.")
        return redirect("panel_tribunal")

    (
        id_acta, goles_local, goles_visita, incidentes,
        amarillas, rojas,
        id_partido, club_local, club_visita,
        fecha, hora, cancha, estado_acta
    ) = info

    # 🔹 Cargar nómina
    nomina_local, nomina_visita = [], []
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT jp.id_club, jp.camiseta,
                   TRIM(COALESCE(j.nombre,'') || ' ' || COALESCE(j.apellido,'')) AS nombre
              FROM jugador_partido jp
              JOIN jugadores j ON j.rut_jugador = jp.rut_jugador
             WHERE jp.id_partido = %s
          ORDER BY jp.id_club ASC, jp.camiseta ASC, nombre ASC;
        """, [id_partido])
        rows = cursor.fetchall()

        # Obtener clubes asociados
        cursor.execute("SELECT id_club_local, id_club_visitante FROM partidos WHERE id_partido = %s", [id_partido])
        id_local, id_visita = cursor.fetchone()

    for id_club, camiseta, nombre in rows:
        jugador = {"camiseta": camiseta, "nombre": nombre or ""}
        if id_club == id_local:
            nomina_local.append(jugador)
        elif id_club == id_visita:
            nomina_visita.append(jugador)

    # 🔹 Procesar acción del tribunal (Aprobar / Devolver)
    if request.method == "POST":
        nuevo_estado = request.POST.get("estado")
        observacion = request.POST.get("observacion", "").strip()

        with connection.cursor() as cursor:
            cursor.execute("""
                UPDATE estado_acta
                   SET nombre_estado = %s,
                       descripcion = %s
                 WHERE id_acta = %s;
            """, [
                nuevo_estado,
                observacion or f"Estado actualizado a '{nuevo_estado}' por el Tribunal.",
                id_acta
            ])

        messages.success(request, f"✅ Acta #{id_acta} actualizada a '{nuevo_estado}'.")
        return redirect("panel_tribunal")

    # 🔹 Contexto
    contexto = {
        "id_acta": id_acta,
        "club_local": club_local,
        "club_visita": club_visita,
        "fecha": fecha,
        "hora": hora,
        "cancha": cancha,
        "estado_acta": estado_acta,
        "goles_local": goles_local,
        "goles_visita": goles_visita,
        "amarillas": amarillas,
        "rojas": rojas,
        "incidentes": incidentes,
        "nomina_local": nomina_local,
        "nomina_visita": nomina_visita,
    }

    return render(request, "accounts/ver_acta.html", contexto)




# ============================================================
# HISTORIAL Y DETALLE DE ACTAS DEL ÁRBITRO
# ============================================================
from django.core.paginator import Paginator

@role_required("Arbitro")
def actas_arbitro(request):
    rut, dv = _parse_rut_from_session(request)
    id_ver = request.GET.get("ver")  # parámetro ?ver=<id_acta>

    with connection.cursor() as cursor:
        # 🔹 Si se solicita ver una acta específica
        if id_ver:
            cursor.execute("""
                SELECT 
                    a.id_acta,
                    p.club_local,
                    p.club_visitante,
                    p.fecha,
                    p.hora,
                    COALESCE(ca.nombre, 'Cancha sin asignar') AS cancha,
                    a.goles_local,
                    a.goles_visita,
                    a.incidentes,
                    COALESCE(ea.nombre_estado, 'Pendiente') AS estado,
                    COALESCE(ea.descripcion, '') AS descripcion
                FROM acta_partido a
                JOIN partidos p ON p.id_partido = a.id_partido
                LEFT JOIN cancha ca ON ca.id_cancha = p.id_cancha
                LEFT JOIN estado_acta ea ON ea.id_acta = a.id_acta
                WHERE a.id_acta = %s
                LIMIT 1;
            """, [id_ver])
            acta = cursor.fetchone()

            # 🔸 Validar existencia
            if not acta:
                messages.warning(request, "El acta no está disponible o fue eliminada.")
                return redirect("actas_arbitro")

            return render(request, "accounts/ver_acta.html", {"acta": acta})

        # 🔹 Listado general de actas
        cursor.execute("""
            SELECT 
                a.id_acta,
                p.club_local,
                p.club_visitante,
                p.fecha,
                a.goles_local,
                a.goles_visita,
                COALESCE(a.incidentes, 'Sin incidentes') AS incidentes,
                COALESCE(ea.nombre_estado, 'Pendiente') AS estado
            FROM acta_partido a
            JOIN partidos p ON a.id_partido = p.id_partido
            LEFT JOIN estado_acta ea ON ea.id_acta = a.id_acta
            WHERE a.rut = %s AND UPPER(a.digitov) = UPPER(%s)
            ORDER BY p.fecha DESC;
        """, [rut, dv])
        actas = cursor.fetchall()

    # 🔹 Aplicar paginación: 9 actas por página (3 filas x 3 columnas)
    paginator = Paginator(actas, 9)
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)

    contexto = {
        "page_obj": page_obj,
        "actas": page_obj.object_list,
    }

    return render(request, "accounts/actas_arbitro.html", contexto)




# ============================================================
# Redacción de Actas - Panel Árbitro
# ============================================================
@role_required("Arbitro")
def redactar_acta(request, id_partido):
    estado_actual = None  # ✅ Evita UnboundLocalError si no hay acta existente

    rut, dv = _parse_rut_from_session(request)

    # 🔹 Obtener datos del partido asignado
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT 
                p.id_partido,
                p.club_local,
                p.club_visitante,
                p.fecha,
                p.hora,
                COALESCE(ca.nombre, 'Cancha sin asignar') AS cancha,
                p.estado,
                p.id_club_local,
                p.id_club_visitante
            FROM partidos p
            LEFT JOIN cancha ca ON ca.id_cancha = p.id_cancha
            WHERE p.id_partido = %s 
              AND p.rut = %s 
              AND UPPER(p.digitov) = UPPER(%s)
            LIMIT 1;
        """, [id_partido, rut, dv])
        partido = cursor.fetchone()

    # 🔸 Validaciones básicas
    if not partido:
        messages.error(request, "❌ No tienes permiso para este partido o no existe.")
        return redirect("partidos_asignados")

    if partido[6] != "Finalizado":
        messages.warning(request, "⚠️ Solo puedes redactar actas de partidos finalizados.")
        return redirect("partidos_asignados")

    id_club_local = partido[7]
    id_club_visita = partido[8]

    # 🔹 Verificar si ya existe un acta para este partido
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT a.id_acta, COALESCE(ea.nombre_estado, 'Pendiente') AS estado
            FROM acta_partido a
            LEFT JOIN estado_acta ea ON ea.id_acta = a.id_acta
            WHERE a.id_partido = %s
            ORDER BY a.id_acta DESC
            LIMIT 1;
        """, [id_partido])
        acta_existente = cursor.fetchone()

    # ============================================================
    # 🔹 Evaluar estado actual del acta (si existe)
    # ============================================================
    if acta_existente:
        id_acta_existente, estado_actual = acta_existente

        if estado_actual in ["Pendiente", "En revisión", "Aprobada"]:
            messages.warning(
                request,
                f"⚠️ Ya existe un acta en estado '{estado_actual}'. No puedes crear otra."
            )
            return redirect("actas_arbitro")

        elif estado_actual == "Rechazada":
            messages.info(
                request,
                "✏️ Este acta fue devuelta por el Tribunal. Puedes editarla y reenviarla."
            )

        elif estado_actual == "Revisión solicitada":
            messages.info(
                request,
                "✏️ El tribunal devolvió esta acta para corrección. "
                "Puedes editarla y volver a enviarla."
            )
    else:
        estado_actual = None

    # 🔹 Cargar NÓMINA del partido
    nomina_local = []
    nomina_visita = []

    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT 
                jp.id_club,
                COALESCE(jp.camiseta, 0) AS camiseta,
                TRIM(COALESCE(j.nombre, '') || ' ' || COALESCE(j.apellido, '')) AS nombre
            FROM jugador_partido jp
            JOIN jugadores j 
              ON j.rut_jugador = jp.rut_jugador
             AND UPPER(COALESCE(j.digitov, '')) = UPPER(COALESCE(jp.digitov, ''))
            WHERE jp.id_partido = %s
            ORDER BY jp.id_club ASC, jp.camiseta ASC, nombre ASC;
        """, [id_partido])
        filas = cursor.fetchall()

    for id_club, camiseta, nombre in filas:
        jugador = {"camiseta": camiseta, "nombre": nombre or ""}
        if id_club_local and id_club == id_club_local:
            nomina_local.append(jugador)
        elif id_club_visita and id_club == id_club_visita:
            nomina_visita.append(jugador)

    # 🔹 Procesar formulario (POST)
    if request.method == "POST":
        goles_local = request.POST.get("goles_local")
        goles_visita = request.POST.get("goles_visita")
        incidentes = request.POST.get("incidentes", "").strip()
        tarjetas_amarillas = request.POST.get("tarjetas_amarillas") or None
        tarjetas_rojas = request.POST.get("tarjetas_rojas") or None

        if goles_local == "" or goles_visita == "":
            messages.warning(request, "⚠️ Debes ingresar los goles de ambos equipos.")
            return redirect(request.path)

        try:
            with connection.cursor() as cursor:
                # 1️⃣ Buscar el acta creada automáticamente por el Turno
                cursor.execute("""
                    SELECT id_acta FROM acta_partido
                    WHERE id_partido = %s
                    ORDER BY id_acta DESC
                    LIMIT 1;
                """, [id_partido])
                acta_existente = cursor.fetchone()

                if acta_existente:
                    id_acta = acta_existente[0]

                    # 2️⃣ Actualizar la información del acta existente
                    cursor.execute("""
                        UPDATE acta_partido
                        SET goles_local = %s,
                            goles_visita = %s,
                            incidentes = %s,
                            tarjetas_amarillas = %s,
                            tarjetas_rojas = %s,
                            fecha_encuentro = %s
                        WHERE id_acta = %s;
                    """, [
                        goles_local, goles_visita, incidentes,
                        tarjetas_amarillas, tarjetas_rojas,
                        partido[3], id_acta
                    ])

                    # 3️⃣ Crear o actualizar el estado del acta a "Pendiente"
                    cursor.execute("""
                        SELECT COUNT(*) FROM estado_acta WHERE id_acta = %s;
                    """, [id_acta])
                    exists = cursor.fetchone()[0]

                    if exists:
                        cursor.execute("""
                            UPDATE estado_acta
                               SET nombre_estado = %s,
                                   descripcion   = %s
                             WHERE id_acta = %s;
                        """, [
                            "Pendiente",
                            "Acta enviada por el árbitro, pendiente de revisión por el Tribunal.",
                            id_acta
                        ])
                    else:
                        cursor.execute("""
                            INSERT INTO estado_acta (id_acta, nombre_estado, descripcion)
                            VALUES (%s, %s, %s);
                        """, [
                            id_acta,
                            "Pendiente",
                            "Acta enviada por el árbitro, pendiente de revisión por el Tribunal."
                        ])

                    print(f"✅ Acta {id_acta} actualizada y enviada al Tribunal.")
                    messages.success(
                        request, 
                        "✅ El acta fue completada y enviada al Tribunal de Disciplina."
                    )

                else:
                    # ⚠️ Si no existe acta previa, se crea una nueva
                    cursor.execute("""
                        INSERT INTO acta_partido (
                            id_partido, rut, digitov, fecha_encuentro,
                            goles_local, goles_visita, incidentes,
                            tarjetas_amarillas, tarjetas_rojas
                        )
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        RETURNING id_acta;
                    """, [
                        partido[0], rut, dv, partido[3],
                        goles_local, goles_visita, incidentes,
                        tarjetas_amarillas, tarjetas_rojas
                    ])
                    id_acta = cursor.fetchone()[0]

                    # Estado inicial "Pendiente"
                    cursor.execute("""
                        INSERT INTO estado_acta (id_acta, nombre_estado, descripcion)
                        VALUES (%s, %s, %s);
                    """, [
                        id_acta,
                        "Pendiente",
                        "Acta enviada por el árbitro, pendiente de revisión por el Tribunal."
                    ])

                    print(f"ℹ️ Acta creada manualmente por el árbitro (id={id_acta}).")
                    messages.success(request, "✅ Acta creada y enviada al Tribunal.")

        except Exception as e:
            print("❌ Error al actualizar o crear acta:", e)
            messages.error(request, f"❌ No se pudo guardar el acta: {e}")

        return redirect("actas_arbitro")

    # 🔹 Mostrar formulario de redacción
    contexto = {
        "partido": {
            "id": partido[0],
            "local": partido[1],
            "visita": partido[2],
            "fecha": partido[3],
            "hora": partido[4],
            "cancha": partido[5],
            "estado": partido[6],
        },
        "nomina_local": nomina_local,
        "nomina_visita": nomina_visita,
    }

    return render(request, "accounts/redactar_actas.html", contexto)



# ============================================================
# DESCARGAR ACTA EN PDF
# ============================================================
from django.http import FileResponse, Http404
from django.contrib import messages
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.lib.utils import ImageReader
import io, os
from django.conf import settings

@role_required("Tribunal de Disciplina")
def descargar_acta_pdf(request, id_acta):
    """
    Genera y descarga el acta en formato PDF con su logo institucional,
    márgenes de 1.5 cm y tamaño carta (Letter).
    """
    try:
        # --- Obtener los datos del acta (incluye resultado) ---
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT 
                    a.id_acta,
                    p.club_local,
                    p.club_visitante,
                    p.fecha,
                    a.goles_local,
                    a.goles_visita,
                    a.incidentes,
                    COALESCE(ea.nombre_estado, 'Pendiente')
                FROM acta_partido a
                JOIN partidos p ON a.id_partido = p.id_partido
                LEFT JOIN estado_acta ea ON ea.id_acta = a.id_acta
                WHERE a.id_acta = %s
                LIMIT 1;
            """, [id_acta])
            acta = cursor.fetchone()
            
        if not acta:
            messages.error(request, "No se encontró el acta solicitada.")
            raise Http404("Acta no encontrada.")

        # --- Variables principales ---
        id_acta, local, visita, fecha, goles_local, goles_visita, incidentes, estado = acta
        g_local = goles_local if goles_local is not None else "—"
        g_visita = goles_visita if goles_visita is not None else "—"
        nombre_archivo = request.GET.get("nombre", f"Acta_{id_acta}.pdf")
        
        # --- Crear el PDF en memoria ---
        buffer = io.BytesIO()
        pdf = canvas.Canvas(buffer, pagesize=letter)
        pdf.setTitle("Acta de Partido")

        ancho, alto = letter
        margen_x = margen_y = 1.5 * cm
        y = alto - margen_y

        # ============================================================
        # LOGO INSTITUCIONAL (arriba a la derecha)
        # ============================================================
        try:
            logo_path = os.path.join(settings.BASE_DIR, "static", "css", "logo_anfa_Ev2", "logo_anfa_Ev2.jpeg")
            if os.path.exists(logo_path):
                with open(logo_path, "rb") as f:
                    logo_img = ImageReader(f)
                pdf.drawImage(
                    logo_img,
                    x=ancho - (margen_x + 4.2 * cm),
                    y=alto - (margen_y + 4.0 * cm),
                    width=3.6 * cm,
                    height=3.6 * cm,
                    preserveAspectRatio=True,
                    mask="auto"
                )
            else:
                print(f"[⚠️] Logo no encontrado en {logo_path}")
        except Exception as e:
            print(f"[⚠️] Error al insertar el logo: {e}")

        # ============================================================
        # ENCABEZADO DEL DOCUMENTO
        # ============================================================
        pdf.setFont("Helvetica-Bold", 16)
        pdf.drawString(margen_x, y, "ASOCIACIÓN REGIONAL DE FÚTBOL AMATEUR - OCTAVA REGIÓN")
        y -= 25
        pdf.setFont("Helvetica-Bold", 12)
        pdf.drawString(margen_x, y, "Tribunal de Disciplina - ANFA Bío Bío Arauco")
        y -= 25

        pdf.setFont("Helvetica-Bold", 16)
        pdf.drawCentredString(ancho / 2, y, "ACTA DE PARTIDO")
        y -= 35

        # ============================================================
        # INFORMACIÓN PRINCIPAL DEL ACTA
        # ============================================================
        pdf.setFont("Helvetica", 12)
        pdf.drawString(margen_x, y, f"Fecha del partido: {fecha.strftime('%d/%m/%Y')}")
        y -= 20
        pdf.drawString(margen_x, y, f"Encuentro: {local} vs {visita}")
        y -= 20
        ##pdf.drawString(margen_x, y, f"Estado actual del acta: {estado}")
        ##y -= 35
        
    
        # ============================================================
        # INCIDENTES / OBSERVACIONES
        # ============================================================
        pdf.setFont("Helvetica-Bold", 12)
        pdf.drawString(margen_x, y, "Incidentes / Observaciones:")
        y -= 20

        pdf.setFont("Helvetica", 11)
        texto = incidentes or "Sin incidentes registrados."
        text_obj = pdf.beginText(margen_x, y)
        text_obj.setLeading(15)
        text_obj.textLines(texto)
        pdf.drawText(text_obj)
        y -= (len(texto.split("\n")) * 15) + 60
        
         # ============================================================
        # MARCADOR VISUAL (Logos y resultado grande)
        # ============================================================
        import unicodedata, re

        def normalizar_nombre(nombre):
            """Convierte 'Magallanes Sur' → 'magallanes_sur' y elimina acentos."""
            nombre = unicodedata.normalize('NFKD', nombre).encode('ascii', 'ignore').decode('utf-8')
            nombre = re.sub(r'\s+', '_', nombre.strip())  # reemplaza espacios por _
            return nombre.lower()

        marcador_y = y - 40  # baja un poco el bloque visual

        # --- Cargar logos de clubes ---
        logo_local_path = os.path.join(settings.BASE_DIR, "static","css","img", f"{normalizar_nombre(local)}.png")
        logo_visita_path = os.path.join(settings.BASE_DIR, "static","css","img", f"{normalizar_nombre(visita)}.png")

        # Posiciones base
        centro_x = ancho / 2
        logo_size = 3.2 * cm  # tamaño un poco mayor

        # Logo local
        try:
            if os.path.exists(logo_local_path):
                pdf.drawImage(logo_local_path, centro_x - 7*cm, marcador_y - 1.2*cm, width=logo_size, height=logo_size, mask='auto')
            else:
                pdf.setFont("Helvetica", 10)
                pdf.drawCentredString(centro_x - 5.5*cm, marcador_y, local)
        except Exception as e:
            print(f"⚠️ No se pudo mostrar logo local: {e}")

        # Logo visita
        try:
            if os.path.exists(logo_visita_path):
                pdf.drawImage(logo_visita_path, centro_x + 4*cm, marcador_y - 1.2*cm, width=logo_size, height=logo_size, mask='auto')
            else:
                pdf.setFont("Helvetica", 10)
                pdf.drawCentredString(centro_x + 5.5*cm, marcador_y, visita)
        except Exception as e:
            print(f"⚠️ No se pudo mostrar logo visitante: {e}")

        # Resultado central
        pdf.setFont("Helvetica-Bold", 30)
        pdf.setFillColor(colors.darkblue)
        pdf.drawCentredString(centro_x, marcador_y + 0.5*cm, f"{g_local}  –  {g_visita}")

        y = marcador_y - 2.5*cm  # espacio inferior para seguir con nómina
        
        
        # ============================================================
        # NÓMINA DE JUGADORES (LOCAL Y VISITA)
        # ============================================================
        try:
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT jp.id_club, jp.camiseta,
                           TRIM(COALESCE(j.nombre,'') || ' ' || COALESCE(j.apellido,'')) AS nombre
                      FROM jugador_partido jp
                      JOIN jugadores j 
                        ON j.rut_jugador = jp.rut_jugador
                     WHERE jp.id_partido = (
                        SELECT id_partido FROM acta_partido WHERE id_acta = %s
                     )
                  ORDER BY jp.id_club ASC, jp.camiseta ASC, nombre ASC;
                """, [id_acta])
                filas = cursor.fetchall()

                cursor.execute("""
                    SELECT id_club_local, id_club_visitante
                    FROM partidos p
                    JOIN acta_partido a ON a.id_partido = p.id_partido
                    WHERE a.id_acta = %s
                    LIMIT 1;
                """, [id_acta])
                id_local, id_visita = cursor.fetchone()

            # Separar listas
            nomina_local = []
            nomina_visita = []
            for id_club, camiseta, nombre in filas:
                jugador = f"#{camiseta} - {nombre}"
                if id_club == id_local:
                    nomina_local.append(jugador)
                elif id_club == id_visita:
                    nomina_visita.append(jugador)

            # --- Dibujar los títulos de ambos bloques ---
            pdf.setFont("Helvetica-Bold", 12)
            pdf.setFillColor(colors.white)
            pdf.setStrokeColor(colors.black)

            # Fondo del encabezado de cada bloque
            pdf.setFillColor(colors.HexColor("#1f2937"))
            pdf.rect(margen_x, y, 9*cm, 18, fill=1)
            pdf.rect(margen_x + 10*cm, y, 9*cm, 18, fill=1)

            pdf.setFillColor(colors.white)
            pdf.drawCentredString(margen_x + 4.5*cm, y + 4, local)
            pdf.drawCentredString(margen_x + 14.5*cm, y + 4, visita)
            y -= 20

            # --- Dibujar los contenedores principales (cuadros grandes) ---
            pdf.setStrokeColor(colors.black)
            pdf.setLineWidth(1)
            pdf.rect(margen_x, y - 230, 9*cm, 230)          # Local
            pdf.rect(margen_x + 10*cm, y - 230, 9*cm, 230)  # Visita

            # --- Contenido de nóminas ---
            pdf.setFont("Helvetica", 10)
            pdf.setFillColor(colors.black)
            offset_local = y - 25
            offset_visita = y - 25

            line_height = 14
            for j in nomina_local[:16]:  # Limitar líneas para evitar desbordes
                pdf.drawString(margen_x + 0.5*cm, offset_local, j)
                offset_local -= line_height

            for j in nomina_visita[:16]:
                pdf.drawString(margen_x + 10.5*cm, offset_visita, j)
                offset_visita -= line_height

            y -= 250

        except Exception as e:
            print("⚠️ Error al agregar nóminas al PDF:", e)


        # ============================================================
        # FIRMA DEL ÁRBITRO (pie de página)
        # ============================================================
        pdf.setStrokeColor(colors.black)
        pdf.line(7*cm, 3.5*cm, 14*cm, 3.5*cm)

        pdf.setFont("Helvetica", 10)
        pdf.drawCentredString(10.5*cm, 3.1*cm, "Firma del Árbitro Responsable")
        pdf.setFont("Helvetica-Oblique", 8)
        pdf.drawCentredString(10.5*cm, 2.7*cm, "(Nombre y RUT)")

        # ============================================================
        # PIE INFORMATIVO
        # ============================================================
        pdf.setFont("Helvetica-Oblique", 9)
        pdf.drawString(margen_x, 1.8*cm, "Sistema ANFA - Tribunal de Disciplina")
        pdf.drawRightString(ancho - margen_x, 1.8*cm, f"Acta Nº {id_acta}")

        pdf.showPage()
        pdf.save()

        # ============================================================
        # RETORNAR ARCHIVO
        # ============================================================
        buffer.seek(0)
        return FileResponse(buffer, as_attachment=True, filename=nombre_archivo)

    except Exception as e:
        print("Error al generar PDF:", e)
        messages.error(request, "Ocurrió un error al generar el PDF del acta.")
        raise Http404("Error generando PDF del acta.")



    

# accounts/views.py
from django.shortcuts import render
from django.db import connection

def _infer_rango_edad(nombre, categoria):
    t = (nombre or categoria or '').lower()
    if '3ra infantil' in t:   return (8, 10)
    if '2da infantil' in t:   return (10, 12)
    if '1ra infantil' in t:   return (12, 14)
    if 'juvenil' in t:        return (15, 18)
    if '3ra adulta' in t:     return (18, None)
    if '2da adulta' in t:     return (18, None)
    if 'honor' in t:          return (18, None)
    if 'super senior' in t:   return (45, None)
    if 'senior' in t:         return (35, None)
    if 'años dor' in t:       return (55, None)
    return (None, None)


# ya lo tienes definido más arriba, si no, déjalo aquí:
def _get_default_torneo_id():
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT id_torneo
              FROM torneo
          ORDER BY id_torneo
             LIMIT 1
        """)
        row = cursor.fetchone()
    return row[0] if row else None


def portal_home(request):
    id_serie = request.GET.get("id_serie")

    # =========================
    # 1) Cargar SERIES
    # =========================
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT id_serie, nombre, COALESCE(categoria,'') 
              FROM serie
          ORDER BY id_serie
        """)
        series_rows = cursor.fetchall()

    series = []
    for sid, nombre, cat in series_rows:
        etiqueta = nombre
        if cat:
            etiqueta = f"{nombre} ({cat})"
        series.append({
            "id": sid,
            "nombre": nombre,
            "categoria": cat,
            "etiqueta": etiqueta,
        })

    # Si no hay series -> solo mostramos vacío
    if not series:
        return render(request, "accounts/home.html", {
            "series": [],
            "serie_sel": None,
            "id_serie": None,
            "posiciones": [],
            "sanciones": [],
            "noticias": [],
        })

    # =========================
    # 2) Elegir serie seleccionada
    # =========================
    if not id_serie or not any(str(s["id"]) == str(id_serie) for s in series):
        id_serie = str(series[0]["id"])

    serie_sel = next(
        (s for s in series if str(s["id"]) == str(id_serie)),
        series[0]
    )

    # =========================
    # 3) Noticias POR SERIE (si existe la tabla)
    # =========================
    noticias = []
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT EXISTS (
                SELECT 1 
                FROM information_schema.tables 
               WHERE table_schema = 'public'
                 AND table_name   = 'noticias'
            );
        """)
        existe_noticias = cursor.fetchone()[0]

        if existe_noticias:
            cursor.execute("""
                SELECT 
                    n.id_noticia,
                    n.titulo,
                    COALESCE(n.resumen, '') AS resumen,
                    n.fecha_publicacion
                FROM noticias n
               WHERE n.id_serie = %s
               ORDER BY n.fecha_publicacion DESC NULLS LAST,
                        n.id_noticia DESC
               LIMIT 10;
            """, [id_serie])

            for row in cursor.fetchall():
                nid, titulo, resumen, fecha_pub = row
                noticias.append({
                    "id_noticia": nid,
                    "titulo": titulo,
                    "resumen": resumen,
                    "fecha": fecha_pub,
                })
        else:
            noticias = []

    # =========================
    # 4) Sanciones del Tribunal FILTRADAS POR SERIE (usando s.id_serie)
    # =========================
    sanciones = []
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT 
                s.id_sancion,
                s.fecha_inc,
                COALESCE(s.tipo,'')      AS tipo,
                COALESCE(s.motivo,'')    AS motivo,
                COALESCE(j.nombre,'')    AS nom_jug,
                COALESCE(j.apellido,'')  AS ape_jug,
                COALESCE(c.nombre,'')    AS nom_club
            FROM sanciones s
            LEFT JOIN jugadores j ON j.rut_jugador = s.id_jugador
            LEFT JOIN club c      ON c.id_club     = s.id_club
           WHERE s.id_serie = %s
         ORDER BY s.fecha_inc DESC NULLS LAST,
                  s.id_sancion DESC
            LIMIT 10
        """, [id_serie])

        for row in cursor.fetchall():
            sid, fecha_inc, tipo, motivo, nom_jug, ape_jug, nom_club = row
            sanciones.append({
                "id_sancion": sid,
                "fecha_inc": fecha_inc,
                "tipo": tipo,
                "motivo": motivo,
                "jugador": (nom_jug + " " + ape_jug).strip(),
                "club": nom_club,
            })

    # =========================
    # 5) Tabla de posiciones POR SERIE
    # =========================
    posiciones = []

    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT
                c.id_club,
                c.nombre AS club,
                COALESCE(SUM(s.pts),0)  AS pts,
                COALESCE(SUM(s.pj),0)   AS pj,
                COALESCE(SUM(s.pg),0)   AS pg,
                COALESCE(SUM(s.pe),0)   AS pe,
                COALESCE(SUM(s.pp),0)   AS pp,
                COALESCE(SUM(s.gf),0)   AS gf,
                COALESCE(SUM(s.gc),0)   AS gc,
                COALESCE(SUM(s.gf),0) - COALESCE(SUM(s.gc),0) AS dg
            FROM club c
            JOIN club_serie cs
                  ON cs.id_club  = c.id_club
                 AND cs.id_serie = %s
            LEFT JOIN (
                -- LOCAL
                SELECT
                    p.id_serie,
                    p.id_club_local AS id_club,
                    1 AS pj,
                    CASE WHEN a.goles_local > a.goles_visita THEN 1 ELSE 0 END AS pg,
                    CASE WHEN a.goles_local = a.goles_visita THEN 1 ELSE 0 END AS pe,
                    CASE WHEN a.goles_local < a.goles_visita THEN 1 ELSE 0 END AS pp,
                    a.goles_local  AS gf,
                    a.goles_visita AS gc,
                    CASE 
                      WHEN a.goles_local > a.goles_visita THEN 3
                      WHEN a.goles_local = a.goles_visita THEN 1
                      ELSE 0
                    END AS pts
                FROM partidos p
                JOIN acta_partido a ON a.id_partido = p.id_partido
                JOIN estado_acta ea 
                  ON ea.id_acta = a.id_acta
                 AND ea.nombre_estado = 'Aprobada'
                WHERE p.estado    = 'Finalizado'
                  AND p.id_serie  = %s

                UNION ALL

                -- VISITA
                SELECT
                    p.id_serie,
                    p.id_club_visitante AS id_club,
                    1 AS pj,
                    CASE WHEN a.goles_visita > a.goles_local THEN 1 ELSE 0 END AS pg,
                    CASE WHEN a.goles_visita = a.goles_local THEN 1 ELSE 0 END AS pe,
                    CASE WHEN a.goles_visita < a.goles_local THEN 1 ELSE 0 END AS pp,
                    a.goles_visita AS gf,
                    a.goles_local  AS gc,
                    CASE 
                      WHEN a.goles_visita > a.goles_local THEN 3
                      WHEN a.goles_visita = a.goles_local THEN 1
                      ELSE 0
                    END AS pts
                FROM partidos p
                JOIN acta_partido a ON a.id_partido = p.id_partido
                JOIN estado_acta ea 
                  ON ea.id_acta = a.id_acta
                 AND ea.nombre_estado = 'Aprobada'
                WHERE p.estado    = 'Finalizado'
                  AND p.id_serie  = %s
            ) s
              ON s.id_club = c.id_club
            GROUP BY c.id_club, c.nombre
            ORDER BY pts DESC, dg DESC, gf DESC, club ASC;
        """, [id_serie, id_serie, id_serie])

        rows = cursor.fetchall()
        posiciones = [
            {
                "club": r[1],
                "pts":  r[2],
                "pj":   r[3],
                "pg":   r[4],
                "pe":   r[5],
                "pp":   r[6],
                "gf":   r[7],
                "gc":   r[8],
                "dg":   r[9],
            }
            for r in rows
        ]

    return render(request, "accounts/home.html", {
        "series": series,
        "serie_sel": serie_sel,
        "id_serie": id_serie,
        "posiciones": posiciones,
        "sanciones": sanciones,
        "noticias": noticias,
    })



def _recalcular_tabla_torneo(id_torneo: int):
    """
    Recalcula completamente la tablaposiciones para un torneo:
    - Usa SOLO actas con estado 'Aprobada'
    - Suma PJ, PG, PE, PP, GF, GC, Pts por club
    - Reemplaza los registros en tablaposiciones para ese torneo
    """
    if not id_torneo:
        return

    stats = {}  # id_club -> acumulados

    with transaction.atomic():
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT 
                    a.id_torneo,
                    p.id_club_local,
                    p.id_club_visitante,
                    a.goles_local,
                    a.goles_visita
                FROM acta_partido a
                JOIN partidos p      ON p.id_partido = a.id_partido
                JOIN estado_acta ea  ON ea.id_acta   = a.id_acta
               WHERE a.id_torneo = %s
                 AND ea.nombre_estado = 'Aprobada';
            """, [id_torneo])
            rows = cursor.fetchall()

        for (id_t, club_local, club_visita, gl, gv) in rows:
            gl = gl or 0
            gv = gv or 0

            for cid in (club_local, club_visita):
                if cid not in stats:
                    stats[cid] = {
                        "pj": 0, "pg": 0, "pe": 0, "pp": 0,
                        "gf": 0, "gc": 0, "pts": 0,
                    }

            stats[club_local]["pj"] += 1
            stats[club_visita]["pj"] += 1

            stats[club_local]["gf"] += gl
            stats[club_local]["gc"] += gv
            stats[club_visita]["gf"] += gv
            stats[club_visita]["gc"] += gl

            if gl > gv:
                stats[club_local]["pg"]  += 1
                stats[club_visita]["pp"] += 1
                stats[club_local]["pts"] += 3
            elif gl < gv:
                stats[club_visita]["pg"]  += 1
                stats[club_local]["pp"]   += 1
                stats[club_visita]["pts"] += 3
            else:
                stats[club_local]["pe"]  += 1
                stats[club_visita]["pe"] += 1
                stats[club_local]["pts"] += 1
                stats[club_visita]["pts"] += 1

        with connection.cursor() as cursor:
            cursor.execute("DELETE FROM tablaposiciones WHERE id_torneo = %s", [id_torneo])

            for club_id, st in stats.items():
                cursor.execute("""
                    INSERT INTO tablaposiciones (
                        pa_jugados,
                        pa_ganados,
                        pa_perdidos,
                        pa_empatados,
                        goles_favor,
                        goles_contra,
                        puntos,
                        id_torneo,
                        id_club
                    )
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """, [
                    st["pj"],
                    st["pg"],
                    st["pp"],
                    st["pe"],
                    st["gf"],
                    st["gc"],
                    st["pts"],
                    id_torneo,
                    club_id,
                ])


# ============================================================
# SECRETARÍA
# ============================================================

def _parse_reunion_desc(desc):
    """
    Descripción guardada como:
    FECHA=2025-11-15;HORA=10:00;LUGAR=Sala X;DETALLE=texto libre
    """
    data = {"fecha": None, "hora": None, "lugar": "", "detalle": desc or ""}
    if not desc:
        return data

    partes = [p for p in desc.split(";") if "=" in p]
    for p in partes:
        k, v = p.split("=", 1)
        k = k.strip().upper()
        v = v.strip()
        if k == "FECHA":
            data["fecha"] = v
        elif k == "HORA":
            data["hora"] = v
        elif k == "LUGAR":
            data["lugar"] = v
        elif k == "DETALLE":
            data["detalle"] = v
    return data


@never_cache
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def panel_secretaria(request):
    # ✅ Debe haber sesión
    if not request.session.get("user_rut"):
        return redirect("login")

    rol = request.session.get("user_rol", "")
    if _normalize_role(rol) not in ("secretario", "secretaria"):
        messages.error(request, "No tienes permisos para acceder a esta página.")
        return redirect("login")

    user_nombre = request.session.get("user_nombre", "Usuario")
    rut, dv = _parse_rut_from_session(request)

    # pestaña activa: reuniones / notificaciones / documentos
    active_tab = request.GET.get("tab") or request.POST.get("tab") or "reuniones"

    # ==========================
    #   ACCIONES POST
    # ==========================
    if request.method == "POST":
        accion = request.POST.get("accion")

        # 🔹 Crear reunión
        if accion == "crear_reunion":
            titulo = (request.POST.get("titulo") or "").strip()
            fecha = request.POST.get("fecha") or ""
            hora = request.POST.get("hora") or ""
            lugar = (request.POST.get("lugar") or "").strip()
            detalle = (request.POST.get("detalle") or "").strip()

            if not titulo or not fecha or not hora or not lugar:
                messages.error(request, "Completa título, fecha, hora y lugar.")
            else:
                desc = f"FECHA={fecha};HORA={hora};LUGAR={lugar};DETALLE={detalle}"
                with connection.cursor() as cursor:
                    cursor.execute("""
                        INSERT INTO anuncio (titulo, fecha_publicacion, descripcion, id_partido, rut, digitov)
                        VALUES (%s, NOW(), %s, NULL, %s, %s)
                    """, [f"[REUNION] {titulo}", desc, rut, dv])
                messages.success(request, "Reunión creada correctamente.")
            return redirect(f"{request.path}?tab=reuniones")

        # 🔹 Eliminar reunión
        if accion == "eliminar_reunion":
            id_anuncio = request.POST.get("id_anuncio")
            if id_anuncio:
                with connection.cursor() as cursor:
                    cursor.execute("DELETE FROM anuncio WHERE id_anuncio = %s", [id_anuncio])
                messages.success(request, "Reunión eliminada.")
            return redirect(f"{request.path}?tab=reuniones")

        # 🔹 Crear notificación
        if accion == "crear_notificacion":
            titulo = (request.POST.get("titulo") or "").strip()
            mensaje = (request.POST.get("mensaje") or "").strip()
            if not titulo or not mensaje:
                messages.error(request, "Debes indicar título y mensaje.")
            else:
                with connection.cursor() as cursor:
                    cursor.execute("""
                        INSERT INTO anuncio (titulo, fecha_publicacion, descripcion, id_partido, rut, digitov)
                        VALUES (%s, NOW(), %s, NULL, %s, %s)
                    """, [f"[NOTIF][PENDIENTE] {titulo}", mensaje, rut, dv])
                messages.success(request, "Notificación creada (pendiente de envío).")
            return redirect(f"{request.path}?tab=notificaciones")

        # 🔹 Enviar notificación (marcar como enviada)
        if accion == "enviar_notificacion":
            id_anuncio = request.POST.get("id_anuncio")
            if id_anuncio:
                with connection.cursor() as cursor:
                    cursor.execute("""
                        UPDATE anuncio
                           SET titulo = REPLACE(titulo, '[PENDIENTE]', '[ENVIADA]')
                         WHERE id_anuncio = %s
                    """, [id_anuncio])
                messages.success(request, "Notificación marcada como enviada.")
            return redirect(f"{request.path}?tab=notificaciones")

        # 🔹 Eliminar notificación
        if accion == "eliminar_notificacion":
            id_anuncio = request.POST.get("id_anuncio")
            if id_anuncio:
                with connection.cursor() as cursor:
                    cursor.execute("DELETE FROM anuncio WHERE id_anuncio = %s", [id_anuncio])
                messages.success(request, "Notificación eliminada.")
            return redirect(f"{request.path}?tab=notificaciones")

        # 🔹 Crear documento (solo registro, sin archivo real)
        if accion == "crear_documento":
            nombre = (request.POST.get("nombre") or "").strip()
            tipo_documento = (request.POST.get("tipo_documento") or "").strip()
            referencia = (request.POST.get("archivo") or "").strip()
            id_club = request.POST.get("id_club") or None

            if not nombre:
                messages.error(request, "Debes indicar el nombre del documento.")
            else:
                with connection.cursor() as cursor:
                    cursor.execute("""
                        INSERT INTO documento (nombre, tipo_documento, archivo, fecha_subida, id_club)
                        VALUES (%s, %s, %s, NOW(), %s)
                    """, [nombre, tipo_documento or None, referencia or None, id_club])
                messages.success(request, "Documento registrado correctamente.")
            return redirect(f"{request.path}?tab=documentos")

        # 🔹 Eliminar documento
        if accion == "eliminar_documento":
            id_documento = request.POST.get("id_documento")
            if id_documento:
                with connection.cursor() as cursor:
                    cursor.execute("DELETE FROM documento WHERE id_documento = %s", [id_documento])
                messages.success(request, "Documento eliminado.")
            return redirect(f"{request.path}?tab=documentos")

    # ==========================
    #   CONSULTAS GET
    # ==========================
    reuniones = []
    notificaciones = []
    documentos = []
    clubs = []
    total_anuncios = 0
    total_docs = 0

    with connection.cursor() as cursor:
        # 🔹 Total anuncios / docs
        cursor.execute("SELECT COUNT(*) FROM anuncio;")
        total_anuncios = cursor.fetchone()[0] or 0

        cursor.execute("SELECT COUNT(*) FROM documento;")
        total_docs = cursor.fetchone()[0] or 0

        # 🔹 Reuniones (anuncios con prefijo [REUNION])
        cursor.execute("""
            SELECT id_anuncio, titulo, fecha_publicacion, descripcion
              FROM anuncio
             WHERE titulo LIKE '[REUNION]%%'
          ORDER BY fecha_publicacion DESC NULLS LAST, id_anuncio DESC;
        """)
        for row in cursor.fetchall():
            aid, titulo_db, fecha_pub, desc = row
            info = _parse_reunion_desc(desc)
            titulo_limpio = titulo_db.replace("[REUNION]", "").strip()
            reuniones.append({
                "id": aid,
                "titulo": titulo_limpio,
                "fecha_evento": info["fecha"] or (fecha_pub.date().isoformat() if fecha_pub else ""),
                "hora": info["hora"] or "",
                "lugar": info["lugar"] or "",
                "detalle": info["detalle"] or "",
            })

        # 🔹 Notificaciones (anuncios con prefijo [NOTIF])
        cursor.execute("""
            SELECT id_anuncio, titulo, fecha_publicacion, descripcion
              FROM anuncio
             WHERE titulo LIKE '[NOTIF]%%'
          ORDER BY fecha_publicacion DESC NULLS LAST, id_anuncio DESC;
        """)
        for row in cursor.fetchall():
            aid, titulo_db, fecha_pub, desc = row
            enviado = "[ENVIADA]" in (titulo_db or "")
            titulo_limpio = (titulo_db or "")
            for mark in ("[NOTIF]", "[PENDIENTE]", "[ENVIADA]"):
                titulo_limpio = titulo_limpio.replace(mark, "")
            titulo_limpio = titulo_limpio.strip()
            notificaciones.append({
                "id": aid,
                "titulo": titulo_limpio,
                "mensaje": desc or "",
                "fecha": fecha_pub.date().isoformat() if fecha_pub else "",
                "enviado": enviado,
            })

        # 🔹 Documentos
        cursor.execute("""
            SELECT d.id_documento, d.nombre, d.tipo_documento, d.archivo, d.fecha_subida,
                   c.nombre AS club_nombre
              FROM documento d
         LEFT JOIN club c ON c.id_club = d.id_club
          ORDER BY d.fecha_subida DESC NULLS LAST, d.id_documento DESC;
        """)
        for row in cursor.fetchall():
            did, nombre, tipo_doc, archivo, fecha_subida, club_nombre = row
            documentos.append({
                "id": did,
                "nombre": nombre,
                "tipo": tipo_doc or "N/D",
                "archivo": archivo or "",
                "fecha": fecha_subida.isoformat() if fecha_subida else "",
                "club": club_nombre or "",
            })

        # 🔹 Clubs para asociar documentos
        cursor.execute("SELECT id_club, nombre FROM club ORDER BY nombre ASC;")
        clubs = [{"id": r[0], "nombre": r[1]} for r in cursor.fetchall()]

    contexto = {
        "user_nombre": user_nombre,
        "active_tab": active_tab,
        "total_anuncios": total_anuncios,
        "total_docs": total_docs,
        "reuniones": reuniones,
        "notificaciones": notificaciones,
        "documentos": documentos,
        "clubs": clubs,
    }
    return render(request, "accounts/secretaria.html", contexto)