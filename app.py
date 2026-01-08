from flask import Flask, render_template, request, redirect, url_for, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)

# CONFIGURACIÓN BASE DE DATOS
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///reciclaje.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'clave_secreta_para_login'

db = SQLAlchemy(app)

# LOGIN MANAGER
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# MODELO USUARIO
class Usuario(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    usuario = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default="usuario")  # <-- NECESARIO

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))


# MODELO RESIDUO
class Residuo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tipo = db.Column(db.String(100), nullable=False)
    descripcion = db.Column(db.String(300), nullable=False)
    color_contenedor = db.Column(db.String(50), nullable=False)
    ejemplos = db.Column(db.String(300), nullable=True)


# CREAR TABLAS
with app.app_context():
    db.create_all()


# RUTA PRINCIPAL
@app.route('/', methods=['GET', 'POST'])
def inicio():
    residuo_consultado = None
    mensaje = ''

    # AGREGAR RESIDUO
    if request.method == 'POST' and 'tipo' in request.form:
        tipo = request.form['tipo']
        descripcion = request.form['descripcion']
        color = request.form['color']
        ejemplos = request.form['ejemplos']

        nuevo = Residuo(
            tipo=tipo,
            descripcion=descripcion,
            color_contenedor=color,
            ejemplos=ejemplos
        )

        db.session.add(nuevo)
        db.session.commit()
        return redirect(url_for('inicio'))

    # CONSULTAR POR ID
    if request.method == 'POST' and 'id_consulta' in request.form:
        id_consulta = request.form['id_consulta']
        residuo_consultado = Residuo.query.get(id_consulta)
        if not residuo_consultado:
            mensaje = f"No se encontró ningún residuo con ID {id_consulta}"

    residuos = Residuo.query.all()

    return render_template(
        'index.html',
        residuos=residuos,
        residuo_consultado=residuo_consultado,
        mensaje=mensaje
    )


# REGISTRO
@app.route('/registro', methods=['GET', 'POST'])
def registro():
    mensaje = None

    if request.method == 'POST':
        usuario = request.form['usuario']
        password = request.form['password']

        existente = Usuario.query.filter_by(usuario=usuario).first()
        if existente:
            return render_template("registro.html", mensaje="Ese usuario ya existe.")

        nuevo = Usuario(usuario=usuario)
        nuevo.set_password(password)

        db.session.add(nuevo)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template("registro.html", mensaje=mensaje)


# LOGIN
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        usuario = request.form['usuario']
        password = request.form['password']

        user = Usuario.query.filter_by(usuario=usuario).first()

        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('inicio'))
        else:
            return render_template('login.html', mensaje="Usuario o contraseña incorrectos")

    return render_template('login.html')


# LOGOUT
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('inicio'))


# ELIMINAR RESIDUO
@app.route('/eliminar', methods=['POST'])
def eliminar():
    id_eliminar = request.form['id']
    residuo = Residuo.query.get(id_eliminar)
    if residuo:
        db.session.delete(residuo)
        db.session.commit()
    return redirect(url_for('inicio'))


# CONSULTAS AVANZADAS
@app.route('/consultas', methods=['GET', 'POST'])
def consultas():
    resultados = None
    mensaje_consulta = ''

    if request.method == 'POST' and 'criterio' in request.form:
        criterio = request.form['criterio']
        valor = request.form.get('valor', '')

        if criterio == 'tipo':
            resultados = Residuo.query.filter(Residuo.tipo.ilike(f"%{valor}%")).all()
        elif criterio == 'color':
            resultados = Residuo.query.filter(Residuo.color_contenedor.ilike(f"%{valor}%")).all()
        elif criterio == 'ejemplos':
            resultados = Residuo.query.filter(Residuo.ejemplos.ilike(f"%{valor}%")).all()

        if not resultados:
            mensaje_consulta = "No se encontraron resultados."

    return render_template(
        'consultas.html',
        resultados=resultados,
        mensaje_consulta=mensaje_consulta
    )





# EJECUTAR APP
if __name__ == "__main__":
    app.run(debug=True)

