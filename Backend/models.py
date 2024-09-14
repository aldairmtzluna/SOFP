from django.db import models

class Cargo(models.Model):
    id_cargo = models.AutoField(primary_key=True)
    nombre_cargo = models.CharField(max_length=15)
    tipo_cargo = models.SmallIntegerField()
    estado_cargo = models.SmallIntegerField()
    fecha_creacion_cargo = models.DateTimeField()
    fecha_modificacion_cargo = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'cargos'

class Rol(models.Model):
    id_rol = models.AutoField(primary_key=True)
    nombre_rol = models.CharField(max_length=15)
    estado_rol = models.SmallIntegerField()
    fecha_creacion_rol = models.DateTimeField()
    fecha_modificacion_rol = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'roles'

class Unidad(models.Model):
    id_unidad = models.AutoField(primary_key=True)
    numero_unidad = models.IntegerField()
    nombre_unidad = models.CharField(max_length=50)
    estado_unidad = models.SmallIntegerField()
    fecha_creacion_unidad = models.DateTimeField()
    fecha_modificacion_unidad = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'unidades'

class Usuario(models.Model):
    id_usuario = models.AutoField(primary_key=True)
    nombre_usuario = models.CharField(max_length=20)
    apellidop_usuario = models.CharField(max_length=10)
    apellidom_usuario = models.CharField(max_length=10)
    correo_usuario = models.EmailField(max_length=30)
    id_rol_usuario = models.ForeignKey(Rol, on_delete=models.CASCADE, db_column='id_rol_usuario')
    id_unidad_usuario = models.ForeignKey(Unidad, on_delete=models.CASCADE, db_column='id_unidad_usuario')
    id_cargo_usuario = models.ForeignKey(Cargo, on_delete=models.CASCADE, db_column='id_cargo_usuario')
    contraseña_usuario = models.CharField(max_length=20)
    estado_usuario = models.SmallIntegerField()
    fecha_creacion_usuario = models.DateTimeField()
    fecha_modificacion_usuario = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'usuarios'
        
class Cargos(models.Model):
    nombre = models.CharField(max_length=100)

    def str(self):
        return self.nombre

class Unidades(models.Model):
    nombre = models.CharField(max_length=100)

    def str(self):
        return self.nombre

class Roles(models.Model):
    nombre = models.CharField(max_length=100)

    def str(self):
        return self.nombre

class Movimientos(models.Model):
    id_movimiento = models.AutoField(primary_key=True)
    tipo_movimiento = models.CharField(max_length=100)
    fecha_creacion_movimiento = models.DateTimeField(auto_now_add=True)
    fecha_modificacion_movimiento = models.DateTimeField(auto_now=True)

    class Meta:
        managed = False  # Esto puede variar dependiendo de tus necesidades
        db_table = 'movimientos'  # Esto debe coincidir con el nombre de la tabla en tu base de datos
        

class MySQLConnection(models.Model):
    id_conexion = models.AutoField(primary_key=True)
    nombre_conexion = models.CharField(max_length=255)
    usuario_conexion = models.CharField(max_length=255)
    password_conexion = models.CharField(max_length=255)
    host_conexion = models.CharField(max_length=255)
    puerto_conexion = models.IntegerField()

    def __str__(self):
        return self.nombre_conexion

    class Meta:
        db_table = 'mysql'
        
        
class PostgreSQLConnection(models.Model):
    id_conexion = models.AutoField(primary_key=True)
    nombre_conexion = models.CharField(max_length=255)
    usuario_conexion = models.CharField(max_length=255)
    password_conexion = models.CharField(max_length=255)
    host_conexion = models.CharField(max_length=255)
    puerto_conexion = models.IntegerField()

    def __str__(self):
        return self.nombre_conexion

    class Meta:
        db_table = 'postgresql'
        
class MongoDbConnection(models.Model):
    id_conexion = models.AutoField(primary_key=True)
    nombre_conexion = models.CharField(max_length=255)
    usuario_conexion = models.CharField(max_length=255)
    password_conexion = models.CharField(max_length=255)
    host_conexion = models.CharField(max_length=255)
    puerto_conexion = models.IntegerField()

    def __str__(self):
        return self.nombre_conexion

    class Meta:
        db_table = 'mongodb'
        
class SqLiteConnection(models.Model):
    id_conexion = models.AutoField(primary_key=True)
    ruta_conexion = models.CharField(max_length=255)

    def __str__(self):
        return self.ruta_conexion

    class Meta:
        db_table = 'sqlite'
        
    