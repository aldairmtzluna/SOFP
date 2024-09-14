from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import Cargo, Unidad, Rol, Usuario, Movimientos
import json
from django.shortcuts import render
from django import forms
from django.db import connections, OperationalError
from django.views import View
from django.utils.decorators import method_decorator
from django.conf import settings
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import base64
import pyodbc
from django.db import transaction
from pymongo import MongoClient
from .utils import generate_key, encrypt_value, decrypt_value
from django.db.utils import OperationalError
import sqlite3
from django.http import JsonResponse, HttpResponseBadRequest
from .models import MySQLConnection, PostgreSQLConnection, MongoDbConnection, SqLiteConnection
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
from .models import MySQLConnection  # Asegúrate de ajustar la importación según la ubicación de tu modelo
from django.contrib.sessions.models import Session


time_zone = getattr(settings, 'TIME_ZONE', 'UTC')

def index(request):
    return render(request)

@csrf_exempt
def ingresar_usuario(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body.decode('utf-8'))
            nuevo_usuario = Usuario.objects.create(
                nombre_usuario=data['nombre'],
                apellidop_usuario=data['apellido_paterno'],
                apellidom_usuario=data['apellido_materno'],
                correo_usuario=data['correo'],
                id_rol_usuario_id=data['id_rol'],
                id_unidad_usuario_id=data['id_unidad'],
                id_cargo_usuario_id=data['id_cargo'],
                contraseña_usuario=data['contrasena'],
                estado_usuario=data['estado'],
                fecha_creacion_usuario=data['fecha_creacion'],
                fecha_modificacion_usuario=data['fecha_modificacion']
            )
            return JsonResponse({'mensaje': 'Usuario ingresado correctamente'})
        except Exception as e:
            return JsonResponse({'error': str(e)})
    else:
        return JsonResponse({'error': 'Método no permitido'})

def cargar_cargos(request):
    cargos = list(Cargo.objects.values('id_cargo', 'nombre_cargo'))
    return JsonResponse({'cargos': cargos})

def cargar_unidades(request):
    unidades = list(Unidad.objects.values('id_unidad', 'nombre_unidad'))
    return JsonResponse({'unidades': unidades})

def cargar_roles(request):
    roles = list(Rol.objects.values('id_rol', 'nombre_rol'))
    return JsonResponse({'roles': roles})

@csrf_exempt
def cargar_usuarios(request):
    if request.method == 'GET':
        usuarios = list(Usuario.objects.values('id_usuario', 'nombre_usuario', 'apellidop_usuario', 'apellidom_usuario', 'correo_usuario',
                                               'id_rol_usuario', 'estado_usuario', 'contraseña_usuario'))
        return JsonResponse({'usuarios': usuarios})
    elif request.method == 'PUT':
        data = json.loads(request.body)
        id_usuario = data.get('id_usuario')
        nuevo_estado = 0 if Usuario.objects.filter(id_usuario=id_usuario, estado_usuario=1).exists() else 1
        Usuario.objects.filter(id_usuario=id_usuario).update(estado_usuario=nuevo_estado)
        return JsonResponse({'message': 'Estado del usuario actualizado correctamente.'})
    else:
        return JsonResponse({'error': 'Método no permitido.'}, status=405)

@csrf_exempt
def cargar_correos(request):
    if request.method == 'GET':
        usuarios = list(Usuario.objects.values('id_usuario', 'correo_usuario'))
        return JsonResponse({'usuarios': usuarios})
    else:
        return JsonResponse({'error': 'Método no permitido.'}, status=405)

@csrf_exempt
def verificar_correo(request):
    if request.method == 'GET':
        correo = request.GET.get('correo', None)
        if correo:
            # Verificar si el correo existe en la tabla de usuarios
            existe = Usuario.objects.filter(correo_usuario=correo).exists()
            return JsonResponse({'existe': existe})
        else:
            return JsonResponse({'error': 'El campo de correo no fue proporcionado'}, status=400)
    else:
        return JsonResponse({'error': 'Método no permitido'}, status=405)

def movimientos_json(request):
    # Obtener todos los movimientos de la base de datos
    movimientos = Movimientos.objects.all()
        
    # Serializar los datos en formato JSON
    data = list(movimientos.values('id_movimiento', 'tipo_movimiento', 'fecha_creacion_movimiento', 'fecha_modificacion_movimiento'))
        
    # Devolver los datos serializados como una respuesta JSON
    return JsonResponse(data, safe=False)


@csrf_exempt
def iniciar_sesion(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        correo = data.get('correo_usuario')
        contraseña = data.get('contraseña_usuario')

        try:
            usuario = Usuario.objects.get(correo_usuario=correo)

            if usuario.estado_usuario == 0:
                return JsonResponse({'mensaje': 'Las credenciales son incorrectas'}, status=400)

            if usuario.contraseña_usuario == contraseña:
                request.session['id_usuario'] = usuario.id_usuario
                request.session['nombre_usuario'] = usuario.nombre_usuario
                request.session['apellido_paterno_usuario'] = usuario.apellidop_usuario
                request.session['apellido_materno_usuario'] = usuario.apellidom_usuario
                request.session['correo_usuario'] = usuario.correo_usuario
                request.session['id_rol_usuario'] = usuario.id_rol_usuario.id_rol 
                request.session['estado_usuario'] = usuario.estado_usuario

                return JsonResponse({
                    'mensaje': 'Inicio de sesión exitoso',
                    'usuario': usuario.nombre_usuario,
                    'token': request.session.session_key,
                    'datos_usuario': {
                        'id_usuario': usuario.id_usuario,
                        'nombre_usuario': usuario.nombre_usuario,
                        'apellido_paterno_usuario': usuario.apellidop_usuario,
                        'apellido_materno_usuario': usuario.apellidom_usuario,
                        'correo_usuario': usuario.correo_usuario,
                        'id_rol_usuario': usuario.id_rol_usuario.id_rol,  
                    }
                })
            else:
                return JsonResponse({'error': 'Contraseña incorrecta'}, status=400)
        except Usuario.DoesNotExist:
            return JsonResponse({'error': 'Correo incorrecto o no registrado'}, status=400)
    else:
        return JsonResponse({'error': 'Método no permitido'}, status=405)

@csrf_exempt
def obtener_usuario_por_id(request, usuario_id):
    if request.method == 'GET':
        try:
            usuario = Usuario.objects.get(id_usuario=usuario_id)
            datos_usuario = {
                'id_usuario': usuario.id_usuario,
                'nombre_usuario': usuario.nombre_usuario,
                'apellidop_usuario': usuario.apellidop_usuario,
                'apellidom_usuario': usuario.apellidom_usuario,
                'correo_usuario': usuario.correo_usuario,
                'id_rol_usuario': usuario.id_rol_usuario.id_rol,
                'nombre_rol_usuario': usuario.id_rol_usuario.nombre_rol,
                'estado_usuario': usuario.estado_usuario,
                # No devolvemos la contraseña en la respuesta
            }
            return JsonResponse(datos_usuario)
        except Usuario.DoesNotExist:
            return JsonResponse({'error': 'Usuario no encontrado'}, status=404)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    elif request.method == 'PUT':
        try:
            data = json.loads(request.body.decode('utf-8'))
            usuario = Usuario.objects.get(id_usuario=usuario_id)
            usuario.nombre_usuario = data.get('nombre_usuario', usuario.nombre_usuario)
            usuario.apellidop_usuario = data.get('apellidop_usuario', usuario.apellidop_usuario)
            usuario.apellidom_usuario = data.get('apellidom_usuario', usuario.apellidom_usuario)
            usuario.correo_usuario = data.get('correo_usuario', usuario.correo_usuario)
            usuario.id_rol_usuario_id = data.get('id_rol_usuario', usuario.id_rol_usuario_id)
            usuario.estado_usuario = data.get('estado_usuario', usuario.estado_usuario)
            usuario.contraseña_usuario = data.get('contraseña_usuario', usuario.contraseña_usuario)
            usuario.save()
            return JsonResponse({'mensaje': 'Usuario actualizado correctamente'})
        except Usuario.DoesNotExist:
            return JsonResponse({'error': 'Usuario no encontrado'}, status=404)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Método no permitido'}, status=405)

# Métodos de ofuscación

def generate_key():
    return os.urandom(32)  # Genera una clave de 256 bits

def encrypt_value(value, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(value.encode()) + padder.finalize()

    encrypted_value = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + encrypted_value).decode('utf-8')

def decrypt_value(encrypted_value, key):
    encrypted_value = base64.b64decode(encrypted_value.encode('utf-8'))
    iv = encrypted_value[:16]
    encrypted_value = encrypted_value[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_value = decryptor.update(encrypted_value) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    decrypted_value = unpadder.update(decrypted_padded_value) + unpadder.finalize()
    return decrypted_value.decode('utf-8')

# Metodo para hacer la segunda conexión a MySQL

@method_decorator(csrf_exempt, name='dispatch')
class UpdateDatabaseConfigView(View):
    def post(self, request, *args, **kwargs):
        try:
            data = json.loads(request.body)

            # Extraer los datos del formulario
            db_name = data.get('nombre_conexion')
            db_user = data.get('usuario_conexion')
            db_password = data.get('password_conexion')
            db_host = data.get('host_conexion')
            db_port = data.get('puerto_conexion')

            # Clonar la configuración existente y actualizar los valores de MySQL
            new_db_config = settings.DATABASES['default'].copy()
            new_db_config.update({
                'ENGINE': 'django.db.backends.mysql',
                'NAME': db_name,
                'USER': db_user,
                'PASSWORD': db_password,
                'HOST': db_host,
                'PORT': db_port,
                'ATOMIC_REQUESTS': True,
            })

            settings.DATABASES['mysql'] = new_db_config

            # Forzar el cierre de la conexión para asegurarse de que se use la nueva configuración
            connections['mysql'].close()

            return JsonResponse({'message': 'Configuración de la base de datos actualizada correctamente.'}, status=200)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

# Metodo para imprimir las tablas de la base de datos MySQL

@method_decorator(csrf_exempt, name='dispatch')
class GetTableNamesView(View):
    def post(self, request, *args, **kwargs):
        return self.get_table_names()

    def get(self, request, *args, **kwargs):
        return self.get_table_names()

    def get_table_names(self):
        try:
            # Asegurarse de que la configuración de la base de datos MySQL esté actualizada
            connection = connections['mysql']
            
            with connection.cursor() as cursor:
                cursor.execute("SHOW TABLES")
                tables = cursor.fetchall()
            
            table_names = [table[0] for table in tables]

            return JsonResponse({'tables': table_names}, status=200)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

# Metodo para obtener columnas y registros de las tablas seleccionadas

@method_decorator(csrf_exempt, name='dispatch')
class GetTableDataView(View):
    def post(self, request, *args, **kwargs):
        try:
            data = json.loads(request.body)
            tables = data.get('tables', [])
            
            if not tables:
                return JsonResponse({'error': 'No tables provided'}, status=400)
            
            connection = connections['mysql']
            table_data = {}

            with connection.cursor() as cursor:
                for table in tables:
                    cursor.execute(f"SHOW COLUMNS FROM {table}")
                    columns = [col[0] for col in cursor.fetchall()]
                    
                    cursor.execute(f"SELECT * FROM {table}")
                    rows = cursor.fetchall()
                    
                    table_data[table] = {
                        'columns': columns,
                        'rows': rows
                    }

            return JsonResponse({'data': table_data}, status=200)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

# Metodo para aplicar cifrado AES en la base de datos

@method_decorator(csrf_exempt, name='dispatch')
class MaskTableDataView(View):
    def post(self, request, *args, **kwargs):
        try:
            data = json.loads(request.body)
            table = data.get('table')
            columns = data.get('columns', [])

            if not table or not columns:
                return JsonResponse({'error': 'Table and columns must be provided'}, status=400)

            connection = connections['mysql']

            with connection.cursor() as cursor:
                cursor.execute(f"SHOW COLUMNS FROM {table}")
                all_columns = [col[0] for col in cursor.fetchall()]

                for col in columns:
                    original_column_name = f"original_{col}"
                    
                    # Crear columna original si no existe
                    if original_column_name not in all_columns:
                        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {original_column_name} TEXT")
                        all_columns.append(original_column_name)

                cursor.execute(f"SELECT * FROM {table}")
                rows = cursor.fetchall()

                for row in rows:
                    primary_key_value = row[0]
                    update_queries = []

                    for col in columns:
                        index = all_columns.index(col)
                        original_value = str(row[index])
                        original_column_name = f"original_{col}"
                        key = generate_key()
                        encrypted_value = encrypt_value(original_value, key)
                        update_queries.append(f"{col} = '{encrypted_value}'")
                        cursor.execute(f"UPDATE {table} SET {original_column_name} = '{original_value}' WHERE {all_columns[0]} = '{primary_key_value}'")

                    if update_queries:
                        update_clause = ", ".join(update_queries)
                        update_query = f"UPDATE {table} SET {update_clause} WHERE {all_columns[0]} = '{primary_key_value}'"
                        cursor.execute(update_query)
                connection.commit()

            return JsonResponse({'status': 'success'}, status=200)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

@method_decorator(csrf_exempt, name='dispatch')
class UnmaskTableDataView(View):
    def post(self, request, *args, **kwargs):
        try:
            data = json.loads(request.body)
            table = data.get('table')
            columns = data.get('columns', [])

            if not table or not columns:
                return JsonResponse({'error': 'Table and columns must be provided'}, status=400)

            connection = connections['mysql']

            with connection.cursor() as cursor:
                cursor.execute(f"SHOW COLUMNS FROM {table}")
                all_columns = [col[0] for col in cursor.fetchall()]

                update_queries = []
                for col in columns:
                    original_column_name = f"original_{col}"
                    if original_column_name in all_columns:
                        # Update all rows in the selected column with their original values
                        update_queries.append(f"{col} = {original_column_name}")

                if update_queries:
                    update_clause = ", ".join(update_queries)
                    update_query = f"UPDATE {table} SET {update_clause}"
                    cursor.execute(update_query)

                    # Remove the original columns
                    for col in columns:
                        original_column_name = f"original_{col}"
                        if original_column_name in all_columns:
                            cursor.execute(f"ALTER TABLE {table} DROP COLUMN {original_column_name}")

                connection.commit()

            return JsonResponse({'status': 'success'}, status=200)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)




@method_decorator(csrf_exempt, name='dispatch')
class UpdateDatabasePostgreConfigView(View):
    def post(self, request, *args, **kwargs):
        try:
            data = json.loads(request.body)
            db_name = data.get('nombre_conexion')
            db_user = data.get('usuario_conexion')
            db_password = data.get('password_conexion')
            db_host = data.get('host_conexion')
            db_port = data.get('puerto_conexion')


            new_db_config = settings.DATABASES['default'].copy()
            new_db_config.update({
                'ENGINE': 'django.db.backends.postgresql',
                'NAME': db_name,
                'USER': db_user,
                'PASSWORD': db_password,
                'HOST': db_host,
                'PORT': db_port,
                'ATOMIC_REQUESTS': True,
            })

            settings.DATABASES['postgresql'] = new_db_config
            connections['postgresql'].close()

            return JsonResponse({'message': 'Configuración de la base de datos actualizada correctamente.'}, status=200)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

@method_decorator(csrf_exempt, name='dispatch')
class GetTableNamesPostgreView(View):
    def post(self, request, *args, **kwargs):
        return self.get_table_names()

    def get(self, request, *args, **kwargs):
        return self.get_table_names()

    def get_table_names(self):
        try:
            connection = connections['postgresql']
            with connection.cursor() as cursor:
                cursor.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'")
                tables = cursor.fetchall()
            
            table_names = [table[0] for table in tables]
            return JsonResponse({'tables': table_names}, status=200)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

@method_decorator(csrf_exempt, name='dispatch')
class GetTableDataPostgreView(View):
    def post(self, request, *args, **kwargs):
        try:
            data = json.loads(request.body)
            tables = data.get('tables', [])
            
            if not tables:
                return JsonResponse({'error': 'No tables provided'}, status=400)
            
            connection = connections['postgresql']
            table_data = {}

            with connection.cursor() as cursor:
                for table in tables:
                    cursor.execute(f"SELECT column_name FROM information_schema.columns WHERE table_name = %s", [table])
                    columns = [col[0] for col in cursor.fetchall()]
                    
                    cursor.execute(f"SELECT * FROM {table}")
                    rows = cursor.fetchall()
                    
                    table_data[table] = {
                        'columns': columns,
                        'rows': rows
                    }

            return JsonResponse({'data': table_data}, status=200)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

@method_decorator(csrf_exempt, name='dispatch')
class MaskTableDataPostgreView(View):
    def post(self, request, *args, **kwargs):
        try:
            data = json.loads(request.body)
            table = data.get('table')
            columns = data.get('columns', [])

            if not table or not columns:
                return JsonResponse({'error': 'Table and columns must be provided'}, status=400)

            connection = connections['postgresql']

            with connection.cursor() as cursor:
                for col in columns:
                    original_column_name = f"original_{col}"

                    cursor.execute(f"SELECT column_name FROM information_schema.columns WHERE table_name = %s AND column_name = %s", [table, original_column_name])
                    if cursor.fetchone() is None:
                        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {original_column_name} TEXT")

                    cursor.execute(f"SELECT {col} FROM {table}")
                    rows = cursor.fetchall()

                    for row in rows:
                        original_value = str(row[0])
                        key = generate_key()
                        encrypted_value = encrypt_value(original_value, key)
                        cursor.execute(f"UPDATE {table} SET {original_column_name} = %s, {col} = %s WHERE {col} = %s", 
                                       [original_value, encrypted_value, original_value])

                connection.commit()
            return JsonResponse({'status': 'success'}, status=200)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

@method_decorator(csrf_exempt, name='dispatch')
class UnmaskTableDataPostgreView(View):
    def post(self, request, *args, **kwargs):
        try:
            data = json.loads(request.body)
            table = data.get('table')
            columns = data.get('columns', [])

            if not table or not columns:
                return JsonResponse({'error': 'Table and columns must be provided'}, status=400)

            connection = connections['postgresql']

            with connection.cursor() as cursor:
                update_queries = []
                drop_columns = []

                for col in columns:
                    original_column_name = f"original_{col}"
                    cursor.execute(f"SELECT {original_column_name}, {col} FROM {table}")
                    rows = cursor.fetchall()

                    for row in rows:
                        original_value = row[0]
                        update_queries.append(f"{col} = '{original_value}' WHERE {original_column_name} = '{original_value}'")
                    
                    drop_columns.append(original_column_name)

                if update_queries:
                    for query in update_queries:
                        cursor.execute(f"UPDATE {table} SET {query}")

                for original_col in drop_columns:
                    cursor.execute(f"ALTER TABLE {table} DROP COLUMN {original_col}")

                connection.commit()
            return JsonResponse({'status': 'success'}, status=200)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)






# Diccionario para almacenar las conexiones activas
active_connections = {}

@csrf_exempt
def update_mongo_connection(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        db_name = data.get('db_name')
        host = data.get('host', 'localhost')
        port = data.get('port', 27017)
        username = data.get('username', '')
        password = data.get('password', '')

        # Crear nueva conexión
        client = MongoClient(host, port, username=username, password=password)
        db = client[db_name]

        # Almacenar la conexión activa
        active_connections['active'] = db

        return JsonResponse({'message': f'Connected to {db_name} database.'})

@csrf_exempt
def get_collection_names(request):
    if 'active' in active_connections:
        db = active_connections['active']
        collections = db.list_collection_names()
        return JsonResponse({'collections': collections})
    else:
        return JsonResponse({'error': 'No active database connection.'}, status=400)

@csrf_exempt
def get_collection_data(request):
    if 'active' in active_connections:
        db = active_connections['active']
        data = json.loads(request.body)
        collection_name = data.get('collection_name')
        collection = db[collection_name]
        documents = list(collection.find())
        return JsonResponse({'documents': documents})
    else:
        return JsonResponse({'error': 'No active database connection.'}, status=400)




@csrf_exempt
def get_collection_columns(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        collection_name = data.get('collection_name')

        if 'active' in active_connections:
            db = active_connections['active']
            collection = db[collection_name]

            # Obtener una muestra de documentos para extraer los campos
            sample_doc = collection.find_one()
            if sample_doc:
                columns = list(sample_doc.keys())
                return JsonResponse({'columns': columns})
            else:
                return JsonResponse({'error': 'No documents found in the collection.'}, status=404)
        else:
            return JsonResponse({'error': 'No active database connection.'}, status=400)


@csrf_exempt
def obfuscate_collection_data(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        collection_name = data.get('collection_name')
        columns = data.get('columns', [])

        if 'active' in active_connections:
            db = active_connections['active']
            collection = db[collection_name]
            key = generate_key()  # Genera una clave para cifrar

            for doc in collection.find():
                update = {}
                for column in columns:
                    if column in doc:
                        original_column = f"original_{column}"
                        update[original_column] = doc[column]
                        update[column] = encrypt_value(doc[column], key)
                if update:
                    collection.update_one({'_id': doc['_id']}, {'$set': update})

            return JsonResponse({'message': 'Data obfuscated successfully.', 'key': key})
        else:
            return JsonResponse({'error': 'No active database connection.'}, status=400)


@csrf_exempt
def deobfuscate_collection_data(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        collection_name = data.get('collection_name')
        columns = data.get('columns', [])
        key = data.get('key')  # La clave usada para cifrar

        if 'active' in active_connections:
            db = active_connections['active']
            collection = db[collection_name]

            for doc in collection.find():
                set_update = {}
                unset_update = {}

                for column in columns:
                    original_column = f"original_{column}"
                    if original_column in doc:
                        set_update[column] = doc[original_column]
                        unset_update[original_column] = ""

                if set_update:
                    collection.update_one({'_id': doc['_id']}, {'$set': set_update})
                if unset_update:
                    collection.update_one({'_id': doc['_id']}, {'$unset': unset_update})

            return JsonResponse({'message': 'Data deobfuscated successfully.'})
        else:
            return JsonResponse({'error': 'No active database connection.'}, status=400)








@csrf_exempt
def connect_sqlite(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body.decode('utf-8'))
            
        except json.JSONDecodeError as e:
            
            return JsonResponse({'message': 'Invalid JSON', 'error': str(e)}, status=400)
        
        form = SQLiteConnectionForm(data)
        if form.is_valid():
            database_path = form.cleaned_data['database_path']
            # Configura dinámicamente la conexión a la base de datos SQLite
            connections.databases['sqlite_dynamic'] = {
                'ENGINE': 'django.db.backends.sqlite3',
                'NAME': database_path,
                'TIME_ZONE': 'UTC',  # Asegurarse de que TIME_ZONE está presente
                'CONN_MAX_AGE': 0,  # Añadir CONN_MAX_AGE
                'CONN_HEALTH_CHECKS': False,  # Añadir CONN_HEALTH_CHECKS
                'AUTOCOMMIT': True,  # Añadir AUTOCOMMIT
                'ATOMIC_REQUESTS': False,  # Añadir ATOMIC_REQUESTS
                'OPTIONS': {
                    'timeout': 20,
                }
            }
            # Prueba la conexión y obtiene las tablas
            try:
                cursor = connections['sqlite_dynamic'].cursor()
                cursor.execute('SELECT name FROM sqlite_master WHERE type="table"')
                tables = cursor.fetchall()
                cursor.close()
                table_names = [table[0] for table in tables]
                return JsonResponse({'message': 'Conexión exitosa', 'tables': table_names})
            except OperationalError as e:
                
                return JsonResponse({'message': f'No se pudo conectar a la base de datos SQLite: {str(e)}'}, status=400)
        else:
            
            return JsonResponse({'message': 'Formulario inválido', 'errors': form.errors}, status=400)
    else:
        return JsonResponse({'message': 'Método no permitido'}, status=405)
    
active_connection = {}

@csrf_exempt
def connect_sqlite(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        database_path = data.get('database_path')

        try:
            conn = sqlite3.connect(database_path)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = cursor.fetchall()
            table_names = [table[0] for table in tables]

            active_connection['conn'] = conn

            return JsonResponse({'message': 'Conectado a la base de datos.', 'tables': table_names})
        except sqlite3.Error as e:
            return JsonResponse({'message': f'Error al conectar a la base de datos: {str(e)}'}, status=400)

@csrf_exempt
def get_columns(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        table_name = data.get('table_name')
        database_path = data.get('database_path')  # Recibir la ruta de la base de datos

        try:
            conn = sqlite3.connect(database_path)
            cursor = conn.cursor()
            cursor.execute(f"PRAGMA table_info({table_name})")
            columns = cursor.fetchall()
            column_names = [column[1] for column in columns]
            conn.close()
            return JsonResponse({'columns': column_names})
        except sqlite3.Error as e:
            return JsonResponse({'error': str(e)}, status=500)

@csrf_exempt
def obfuscate_data(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        table_name = data.get('table_name')
        columns = data.get('columns', [])
        database_path = data.get('database_path')

        try:
            conn = sqlite3.connect(database_path)
            cursor = conn.cursor()
            key = generate_key()
            encoded_key = base64.b64encode(key).decode('utf-8')

            for column in columns:
                cursor.execute(f"SELECT rowid, {column} FROM {table_name}")
                rows = cursor.fetchall()
                for row in rows:
                    encrypted_value = encrypt_value(row[1], key)
                    cursor.execute(f"UPDATE {table_name} SET {column} = ? WHERE rowid = ?", (encrypted_value, row[0]))

            conn.commit()
            conn.close()
            return JsonResponse({'message': 'Data obfuscated successfully.', 'key': encoded_key})
        except sqlite3.Error as e:
            return JsonResponse({'error': str(e)}, status=500)

@csrf_exempt
def deobfuscate_data(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        table_name = data.get('table_name')
        columns = data.get('columns', [])
        key = base64.b64decode(data.get('key'))
        database_path = data.get('database_path')

        try:
            conn = sqlite3.connect(database_path)
            cursor = conn.cursor()

            for column in columns:
                cursor.execute(f"SELECT rowid, {column} FROM {table_name}")
                rows = cursor.fetchall()
                for row in rows:
                    decrypted_value = decrypt_value(row[1], key)
                    cursor.execute(f"UPDATE {table_name} SET {column} = ? WHERE rowid = ?", (decrypted_value, row[0]))

            conn.commit()
            conn.close()
            return JsonResponse({'message': 'Data deobfuscated successfully.'})
        except sqlite3.Error as e:
            return JsonResponse({'error': str(e)}, status=500)
        
class SQLiteConnectionForm(forms.Form):
    database_path = forms.CharField(label='Ruta de la Base de Datos SQLite',max_length=255)
    
    


@csrf_exempt
def create_mysql_connection(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            mysql_connection = MySQLConnection(
                nombre_conexion=data.get('nombre_conexion'),
                usuario_conexion=data.get('usuario_conexion'),
                password_conexion=data.get('password_conexion'),
                host_conexion=data.get('host_conexion'),
                puerto_conexion=data.get('puerto_conexion')
            )
            mysql_connection.save()
            return JsonResponse({'message': 'Conexión MySQL creada con éxito.'}, status=201)
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            return HttpResponseBadRequest(f'Error en los datos proporcionados: {e}')
    return HttpResponseBadRequest('Método no permitido.')

class MySQLConnectionsList(APIView):
    def get(self, request):
        # Obtener todos los registros de la tabla 'mysql'
        conexiones = MySQLConnection.objects.all()
        # Convertir los registros a un diccionario
        data = [
            {
                "id": conexion.id_conexion,
                "nombre": conexion.nombre_conexion
            }
            for conexion in conexiones
        ]
        # Retornar los datos en formato JSON
        return Response({"basesDatos": data}, status=status.HTTP_200_OK)
    
    
@csrf_exempt
def create_postgresql_connection(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            postgresql_connection = PostgreSQLConnection(
                nombre_conexion=data.get('nombre_conexion'),
                usuario_conexion=data.get('usuario_conexion'),
                password_conexion=data.get('password_conexion'),
                host_conexion=data.get('host_conexion'),
                puerto_conexion=data.get('puerto_conexion')
            )
            postgresql_connection.save()
            return JsonResponse({'message': 'Conexión PostgreSQL creada con éxito.'}, status=201)
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            return HttpResponseBadRequest(f'Error en los datos proporcionados: {e}')
    return HttpResponseBadRequest('Método no permitido.')


class PostgreSQLConnectionsList(APIView):
    def get(self, request):
        # Obtener todos los registros de la tabla 'mysql'
        conexiones = PostgreSQLConnection.objects.all()
        # Convertir los registros a un diccionario
        data = [
            {
                "id": conexion.id_conexion,
                "nombre": conexion.nombre_conexion
            }
            for conexion in conexiones
        ]
        # Retornar los datos en formato JSON
        return Response({"basesDatos": data}, status=status.HTTP_200_OK)
    
@csrf_exempt
def create_mongodb_connection(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            mongodb_connection = MongoDbConnection(
                nombre_conexion=data.get('nombre_conexion'),
                usuario_conexion=data.get('usuario_conexion'),
                password_conexion=data.get('password_conexion'),
                host_conexion=data.get('host_conexion'),
                puerto_conexion=data.get('puerto_conexion')
            )
            mongodb_connection.save()
            return JsonResponse({'message': 'Conexión MySQL creada con éxito.'}, status=201)
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            return HttpResponseBadRequest(f'Error en los datos proporcionados: {e}')
    return HttpResponseBadRequest('Método no permitido.')

class MongoDbConnectionsList(APIView):
    def get(self, request):
        # Obtener todos los registros de la tabla 'mysql'
        conexiones = MongoDbConnection.objects.all()
        # Convertir los registros a un diccionario
        data = [
            {
                "id": conexion.id_conexion,
                "nombre": conexion.nombre_conexion
            }
            for conexion in conexiones
        ]
        # Retornar los datos en formato JSON
        return Response({"basesDatos": data}, status=status.HTTP_200_OK)
    
    
@csrf_exempt
def create_sqlite_connection(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            sqlite_connection = SqLiteConnection(
                ruta_conexion=data.get('ruta_conexion'),
            )
            sqlite_connection.save()
            return JsonResponse({'message': 'Conexión SqLite creada con éxito.'}, status=201)
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            return HttpResponseBadRequest(f'Error en los datos proporcionados: {e}')
    return HttpResponseBadRequest('Método no permitido.')


class SqLiteConnectionsList(APIView):
    def get(self, request):
        # Obtener todos los registros de la tabla 'mysql'
        conexiones = SqLiteConnection.objects.all()
        # Convertir los registros a un diccionario
        data = [
            {
                "id": conexion.id_conexion,
                "ruta": conexion.ruta_conexion
            }
            for conexion in conexiones
        ]
        # Retornar los datos en formato JSON
        return Response({"basesDatos": data}, status=status.HTTP_200_OK)
    
@csrf_exempt
def obtener_conexion_por_id(request, id_conexion):
    if request.method == 'GET':
        try:
            # Obtener la conexión por id
            conexion = MySQLConnection.objects.get(id_conexion=id_conexion)
            datos_conexion = {
                'id_conexion': conexion.id_conexion,
                'nombre_conexion': conexion.nombre_conexion,
                'usuario_conexion': conexion.usuario_conexion,
                'password_conexion': conexion.password_conexion,
                'host_conexion': conexion.host_conexion,
                'puerto_conexion': conexion.puerto_conexion
            }
            return JsonResponse(datos_conexion)
        except MySQLConnection.DoesNotExist:
            return JsonResponse({'error': 'Conexión no encontrada'}, status=404)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    elif request.method == 'PUT':
        try:
            data = json.loads(request.body.decode('utf-8'))
            # Obtener la conexión por id
            conexion = MySQLConnection.objects.get(id_conexion=id_conexion)
            # Actualizar los campos con los datos proporcionados
            conexion.nombre_conexion = data.get('nombre_conexion', conexion.nombre_conexion)
            conexion.usuario_conexion = data.get('usuario_conexion', conexion.usuario_conexion)
            conexion.password_conexion = data.get('password_conexion', conexion.password_conexion)
            conexion.host_conexion = data.get('host_conexion', conexion.host_conexion)
            conexion.puerto_conexion = data.get('puerto_conexion', conexion.puerto_conexion)
            # Guardar los cambios
            conexion.save()
            return JsonResponse({'mensaje': 'Conexión actualizada correctamente'})
        except MySQLConnection.DoesNotExist:
            return JsonResponse({'error': 'Conexión no encontrada'}, status=404)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Método no permitido'}, status=405)
    
    
@csrf_exempt
def obtener_conexion_postgresql_por_id(request, id_conexion):
    if request.method == 'GET':
        try:
            # Obtener la conexión por id
            conexion = PostgreSQLConnection.objects.get(id_conexion=id_conexion)
            datos_conexion = {
                'id_conexion': conexion.id_conexion,
                'nombre_conexion': conexion.nombre_conexion,
                'usuario_conexion': conexion.usuario_conexion,
                'password_conexion': conexion.password_conexion,
                'host_conexion': conexion.host_conexion,
                'puerto_conexion': conexion.puerto_conexion
            }
            return JsonResponse(datos_conexion)
        except PostgreSQLConnection.DoesNotExist:
            return JsonResponse({'error': 'Conexión no encontrada'}, status=404)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    elif request.method == 'PUT':
        try:
            data = json.loads(request.body.decode('utf-8'))
            # Obtener la conexión por id
            conexion = PostgreSQLConnection.objects.get(id_conexion=id_conexion)
            # Actualizar los campos con los datos proporcionados
            conexion.nombre_conexion = data.get('nombre_conexion', conexion.nombre_conexion)
            conexion.usuario_conexion = data.get('usuario_conexion', conexion.usuario_conexion)
            conexion.password_conexion = data.get('password_conexion', conexion.password_conexion)
            conexion.host_conexion = data.get('host_conexion', conexion.host_conexion)
            conexion.puerto_conexion = data.get('puerto_conexion', conexion.puerto_conexion)
            # Guardar los cambios
            conexion.save()
            return JsonResponse({'mensaje': 'Conexión actualizada correctamente'})
        except PostgreSQLConnection.DoesNotExist:
            return JsonResponse({'error': 'Conexión no encontrada'}, status=404)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Método no permitido'}, status=405)
    
       
@csrf_exempt
def obtener_conexion_sqlite_por_id(request, id_conexion):
    if request.method == 'GET':
        try:
            # Obtener la conexión por id
            conexion = SqLiteConnection.objects.get(id_conexion=id_conexion)
            datos_conexion = {
                'id_conexion': conexion.id_conexion,
                'ruta_conexion': conexion.ruta_conexion,
            }
            return JsonResponse(datos_conexion)
        except SqLiteConnection.DoesNotExist:
            return JsonResponse({'error': 'Conexión no encontrada'}, status=404)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    elif request.method == 'PUT':
        try:
            data = json.loads(request.body.decode('utf-8'))
            # Obtener la conexión por id
            conexion = SqLiteConnection.objects.get(id_conexion=id_conexion)
            # Actualizar los campos con los datos proporcionados
            conexion.ruta_conexion = data.get('ruta_conexion', conexion.ruta_conexion)
            # Guardar los cambios
            conexion.save()
            return JsonResponse({'mensaje': 'Conexión actualizada correctamente'})
        except SqLiteConnection.DoesNotExist:
            return JsonResponse({'error': 'Conexión no encontrada'}, status=404)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Método no permitido'}, status=405)
    
    
    
@csrf_exempt
def eliminar_conexion(request, id_conexion):
    if request.method == 'DELETE':
        try:
            # Obtener la conexión por id y eliminarla
            conexion = MySQLConnection.objects.get(id_conexion=id_conexion)
            conexion.delete()
            return JsonResponse({'mensaje': 'Conexión eliminada correctamente'}, status=200)
        except MySQLConnection.DoesNotExist:
            return JsonResponse({'error': 'Conexión no encontrada'}, status=404)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Método no permitido'}, status=405)
    
@csrf_exempt
def eliminar_conexion_postgresql(request, id_conexion):
    if request.method == 'DELETE':
        try:
            # Obtener la conexión por id y eliminarla
            conexion = PostgreSQLConnection.objects.get(id_conexion=id_conexion)
            conexion.delete()
            return JsonResponse({'mensaje': 'Conexión eliminada correctamente'}, status=200)
        except PostgreSQLConnection.DoesNotExist:
            return JsonResponse({'error': 'Conexión no encontrada'}, status=404)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Método no permitido'}, status=405)