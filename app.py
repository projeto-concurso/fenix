from flask import Flask, render_template, redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Defina seu código de admin aqui
ADMIN_CODE = '6.<3nqUV2i0m'

# Adicione o filtro split
def split_filter(value, separator):
    return value.split(separator)

app.jinja_env.filters['split'] = split_filter

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class Questao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    materia = db.Column(db.String(50), nullable=False)
    tema = db.Column(db.String(50), nullable=False)
    banca = db.Column(db.String(50), nullable=False)
    enunciado = db.Column(db.Text, nullable=False)
    tipo = db.Column(db.String(10), nullable=False)
    alternativas = db.Column(db.Text)  # Alternativas separadas por ponto e vírgula
    resposta = db.Column(db.Text, nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        codigo = request.form['codigo']
        is_admin = codigo == ADMIN_CODE
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password, is_admin=is_admin)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/create_question', methods=['GET', 'POST'])
@login_required
def create_question():
    if not current_user.is_admin:
        return redirect(url_for('home'))
    if request.method == 'POST':
        materia = request.form['materia']
        tema = request.form['tema']
        banca = request.form['banca']
        enunciado = request.form['enunciado']
        tipo = request.form['tipo']
        if tipo == 'multipla_escolha':
            alternativas = ';'.join([request.form['alternativa1'], request.form['alternativa2'], request.form['alternativa3'], request.form['alternativa4']])
        else:
            alternativas = ''
        resposta = request.form['resposta']
        nova_questao = Questao(materia=materia, tema=tema, banca=banca, enunciado=enunciado, tipo=tipo, alternativas=alternativas, resposta=resposta)
        db.session.add(nova_questao)
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('create_question.html')

@app.route('/admin/questoes')
@login_required
def admin_questoes():
    if not current_user.is_admin:
        return redirect(url_for('home'))
    questoes = Questao.query.all()
    return render_template('admin_questoes.html', questoes=questoes)

@app.route('/admin/questoes/editar/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_questao(id):
    if not current_user.is_admin:
        return redirect(url_for('home'))
    questao = Questao.query.get_or_404(id)
    if request.method == 'POST':
        questao.materia = request.form['materia']
        questao.tema = request.form['tema']
        questao.banca = request.form['banca']
        questao.enunciado = request.form['enunciado']
        questao.tipo = request.form['tipo']
        if questao.tipo == 'multipla_escolha':
            questao.alternativas = ';'.join([request.form['alternativa1'], request.form['alternativa2'], request.form['alternativa3'], request.form['alternativa4']])
        else:
            questao.alternativas = ''
        questao.resposta = request.form['resposta']
        db.session.commit()
        return redirect(url_for('admin_questoes'))
    return render_template('editar_questao.html', questao=questao)

@app.route('/admin/questoes/excluir/<int:id>')
@login_required
def excluir_questao(id):
    if not current_user.is_admin:
        return redirect(url_for('home'))
    questao = Questao.query.get_or_404(id)
    db.session.delete(questao)
    db.session.commit()
    return redirect(url_for('admin_questoes'))

@app.route('/simulado', methods=['GET', 'POST'])
@login_required
def simulado():
    materias = db.session.query(Questao.materia).distinct().all()
    bancas = db.session.query(Questao.banca).distinct().all()
    temas = db.session.query(Questao.tema).distinct().all()
    questoes = []

    if request.method == 'POST':
        max_questoes = request.form.get('max_questoes', type=int)
        materia = request.form.get('materia')
        banca = request.form.get('banca')
        tema = request.form.get('tema')

        query = Questao.query

        if materia:
            query = query.filter_by(materia=materia)
        if banca:
            query = query.filter_by(banca=banca)
        if tema:
            query = query.filter_by(tema=tema)
        if max_questoes:
            query = query.limit(max_questoes)

        questoes = query.all()

    return render_template('simulado.html', questoes=questoes, materias=materias, bancas=bancas, temas=temas)

@app.route('/submit_simulado', methods=['POST'])
@login_required
def submit_simulado():
    respostas = request.form.to_dict()
    score = 0
    for questao_id, resposta in respostas.items():
        questao = Questao.query.get(int(questao_id))
        if questao.resposta == resposta:
            score += 1
    return render_template('resultado_simulado.html', score=score, total=len(respostas))

if __name__ == '__main__':
    app.run(debug=True)
