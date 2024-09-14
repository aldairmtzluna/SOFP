from django.urls import path
from Backend.views import (
    index, ingresar_usuario, cargar_cargos, cargar_unidades, cargar_roles,
    cargar_usuarios, movimientos_json, cargar_correos, verificar_correo,
    iniciar_sesion, UpdateDatabaseConfigView, GetTableNamesView,
    GetTableDataView, MaskTableDataView,  UnmaskTableDataView, obtener_usuario_por_id,
    UpdateDatabasePostgreConfigView, GetTableNamesPostgreView, GetTableDataPostgreView, MaskTableDataPostgreView, UnmaskTableDataPostgreView,
    update_mongo_connection, get_collection_names, get_collection_data, get_collection_columns, obfuscate_collection_data, 
    deobfuscate_collection_data, connect_sqlite, get_columns, obfuscate_data, deobfuscate_data, create_mysql_connection, MySQLConnectionsList,
    create_postgresql_connection, PostgreSQLConnectionsList, create_mongodb_connection, MongoDbConnectionsList, create_sqlite_connection,
    SqLiteConnectionsList, obtener_conexion_por_id, eliminar_conexion, obtener_conexion_postgresql_por_id, eliminar_conexion_postgresql,
    obtener_conexion_sqlite_por_id
)

urlpatterns = [
    path('', index, name='index'),
    path('ingresar-usuario/', ingresar_usuario, name='ingresar_usuario'),
    path('api/cargar-cargos/', cargar_cargos, name='cargar_cargos'),
    path('api/cargar-unidades/', cargar_unidades, name='cargar_unidades'),
    path('api/cargar-roles/', cargar_roles, name='cargar_roles'),
    path('api/iniciar_sesion/', iniciar_sesion, name='iniciar_sesion'),
    path('api/usuarios/', cargar_usuarios, name='cargar_usuarios'),
    path('api/correos/', cargar_correos, name='cargar_correos'),
    path('api/usuario/<int:usuario_id>/', obtener_usuario_por_id, name='obtener_usuario_por_id'),
    path('api/movimientos/', movimientos_json, name='movimientos_json'),
    path('verificar-correo/', verificar_correo, name='verificar_correo'),

    path('api/mysql/', UpdateDatabaseConfigView.as_view(), name='mysql'),
    path('api/mysql/tablas/', GetTableNamesView.as_view(), name='mysql_tablas'),
    path('api/mysql/tablas/datos/', GetTableDataView.as_view(), name='mysql_tablas_datos'),
    path('api/mysql/tablas/enmascarar/', MaskTableDataView.as_view(), name='mask_table_data'),
    path('api/mysql/tablas/desenmascarar/', UnmaskTableDataView.as_view(), name='unmask_table_data'),

    
    path('api/postgresql/', UpdateDatabasePostgreConfigView.as_view(), name='postgresql'),
    path('api/postgresql/tablas/', GetTableNamesPostgreView.as_view(), name='postgresql_tablas'),
    path('api/postgresql/tablas/datos/', GetTableDataPostgreView.as_view(), name='postgresql_tablas_datos'),
    path('api/postgresql/tablas/enmascarar/', MaskTableDataPostgreView.as_view(), name='mask_table_data'),
    path('api/postgresql/tablas/desenmascarar/', UnmaskTableDataPostgreView.as_view(), name='unmask_table_data'),
    
    path('api/mongo/update/', update_mongo_connection, name='update_mongo_connection'),
    path('api/mongo/collections/', get_collection_names, name='get_collection_names'),
    path('api/mongo/collection/data/', get_collection_data, name='get_collection_data'),
    path('api/mongo/collection/columns/', get_collection_columns, name='get_collection_columns'),
    path('api/mongo/collection/obfuscate/', obfuscate_collection_data, name='obfuscate_collection_data'),
    path('api/mongo/collection/deobfuscate/', deobfuscate_collection_data, name='deobfuscate_collection_data'),

    path('api/connect_sqlite/', connect_sqlite, name='connect_sqlite'),
    path('api/get_columns/', get_columns, name='get_columns'),
    path('api/obfuscate/', obfuscate_data, name='obfuscate_data'),
    path('api/deobfuscate/', deobfuscate_data, name='deobfuscate_data'),
    
    path('api/mysql-connections/', create_mysql_connection, name='mysql-connections-create'),
    path('api/bases-mysql/', MySQLConnectionsList.as_view(), name='mysql-connections-list'),
    
    path('api/postgresql-connections/', create_postgresql_connection, name='postgresql-connections-create'),
    path('api/bases-postgresql/', PostgreSQLConnectionsList.as_view(), name='postgresql-connections-list'),

    path('api/mongodb-connections/', create_mongodb_connection, name='mongodb-connections-create'),
    path('api/bases-mongodb/', MongoDbConnectionsList.as_view(), name='mongodb-connections-list'),
    
    path('api/sqlite-connections/', create_sqlite_connection, name='sqlite-connections-create'),
    path('api/bases-sqlite/', SqLiteConnectionsList.as_view(), name='sqlite-connections-list'),    
    
    
    path('api/cargar-mysql/<int:id_conexion>/', obtener_conexion_por_id, name='cargar-mysql'),
    path('api/cargar-postgresql/<int:id_conexion>/', obtener_conexion_postgresql_por_id, name='cargar-postgresql'),
    path('api/cargar-sqlite/<int:id_conexion>/', obtener_conexion_sqlite_por_id, name='cargar-sqlite'),
    
     path('api/eliminar-mysql/<int:id_conexion>/', eliminar_conexion, name='eliminar-mysql'),
     path('api/eliminar-postgresql/<int:id_conexion>/', eliminar_conexion_postgresql, name='eliminar-postgresql'),
]