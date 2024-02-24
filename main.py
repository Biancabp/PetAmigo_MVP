from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_migrate import Migrate
from flask_login import login_required, current_user, LoginManager, login_user, logout_user
from config import Config
from flask_bcrypt import Bcrypt
from models import db, User, Animal, AdoptionProcess
from forms import RegistrationForm, LoginForm, AddPetForm
from datetime import datetime


app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

app.secret_key = 'your_secret_key'

@app.route('/')
def index():
    # Verifica se o usuário está autenticado e busca as informações do usuário
    if current_user.is_authenticated:
        user = User.query.get(current_user.id)
        if not user:
            abort(404)  # Trate o caso do usuário não ser encontrado
        return render_template('index.html', user=user)
    else:
        flash('Você precisa fazer login para acessar a página inicial.', 'warning')
        return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            name=form.name.data,
            email=form.email.data,
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Cadastro realizado com sucesso! Agora você pode fazer login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if user and user.check_password(form.password.data):
            login_user(user)  # Autentica o usuário
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('index'))

        flash('Credenciais inválidas. Verifique seu e-mail e senha.', 'danger')

    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()  # Realiza o logout do usuário autenticado pelo Flask-Login
    flash('Logout realizado com sucesso!', 'success')
    return redirect(url_for('index'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = User.query.get(current_user.id)
    if not user:
        flash('Usuário não encontrado.', 'danger')
        return redirect(url_for('logout'))

    form = RegistrationForm(obj=user)

    if form.validate_on_submit():
        if form.is_volunteer.data and form.auth_password.data != 'senhamoderador':
            flash('Senha de autorização incorreta. As informações não foram atualizadas.', 'danger')
        else:
            if form.is_volunteer.data and form.auth_password.data == 'senhamoderador':
                user.is_volunteer = True  # Definir como voluntário se a senha de autorização estiver correta
            else:
                user.is_volunteer = False  # Definir como adotante se o checkbox não foi selecionado

            if form.name.data:
                user.name = form.name.data
            if form.email.data:
                user.email = form.email.data
            if form.password.data:
                user.set_password(form.password.data)

            db.session.commit()
            flash('Informações atualizadas com sucesso!', 'success')

            # Verificar se o usuário se tornou voluntário
            if user.is_volunteer:
                flash('Você se tornou um voluntário!', 'success')
            else:
                flash('Você continua sendo um adotante.', 'info')

            return redirect(url_for('profile'))

    return render_template('profile.html', form=form, user=user)

@app.route('/users_list')
@login_required
def users_list():
    # Verifica se o usuário é do tipo voluntário
    if not current_user.is_volunteer:
        abort(403)  # Acesso não autorizado

    users = User.query.all()
    return render_template('users_list.html', users=users)

@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    # Obtemos o usuário autenticado diretamente de current_user
    user = current_user

    # Podemos realizar a exclusão direto no banco de dados utilizando o usuário autenticado
    db.session.delete(user)
    db.session.commit()

    # Após excluir a conta, realizamos o logout do usuário
    logout_user()

    flash('Conta excluída com sucesso! Obrigado por usar nosso sistema.', 'success')
    return redirect(url_for('index'))

@app.route('/pets')
@login_required
def pets():
    # Verifica se o usuário é do tipo VOLUNTARIO
    if not current_user.is_volunteer:
        flash('Acesso não autorizado. Esta página é destinada apenas para voluntários.', 'danger')
        return redirect(url_for('index'))

    animals = Animal.query.all()
    return render_template('pets.html', animals=animals)

@app.route('/add_pet', methods=['GET', 'POST'])
@login_required
def add_pet():
    # Verifica se o usuário é do tipo voluntário
    if not current_user.is_volunteer:
        flash('Acesso não autorizado. Esta página é destinada apenas para voluntários.', 'danger')
        return redirect(url_for('pets'))

    form = AddPetForm()

    if form.validate_on_submit():
        name = form.name.data
        age = form.age.data
        birthdate_str = form.birthdate.data.strftime('%Y-%m-%d')
        birthdate = datetime.strptime(birthdate_str, '%Y-%m-%d').date()
        species = form.species.data
        breed = form.breed.data
        size = form.size.data
        color = form.color.data
        temperament = form.temperament.data
        sex = form.sex.data

        animal = Animal(name=name, age=age, birthdate=birthdate, species=species,
                        breed=breed, size=size, color=color, temperament=temperament, sex=sex)

        db.session.add(animal)
        db.session.commit()
        flash('Animal adicionado com sucesso!', 'success')
        return redirect(url_for('pets'))

    return render_template('add_pet.html', form=form)


@app.route('/pet_details/<int:animal_id>')
@login_required
def pet_details(animal_id):
    # Verifica se o usuário é do tipo voluntário
    if not current_user.is_volunteer:
        flash('Acesso não autorizado. Esta página é destinada apenas para voluntários.', 'danger')
        return redirect(url_for('pets'))

    # Buscar o animal pelo ID no banco de dados
    animal = Animal.query.get(animal_id)
    if not animal:
        flash('Animal não encontrado.', 'danger')
        return redirect(url_for('pets'))

    return render_template('pet_details.html', animal=animal)

@app.route('/delete_pet/<int:animal_id>', methods=['POST'])
@login_required
def delete_pet(animal_id):
    # Verifica se o usuário é do tipo voluntário
    if not current_user.is_volunteer:
        flash('Acesso não autorizado. Esta página é destinada apenas para voluntários.', 'danger')
        return redirect(url_for('pets'))

    # Buscar o animal pelo ID no banco de dados
    animal = Animal.query.get(animal_id)
    if not animal:
        flash('Animal não encontrado.', 'danger')
        return redirect(url_for('pets'))

    db.session.delete(animal)
    db.session.commit()
    flash('Animal excluído com sucesso!', 'success')
    return redirect(url_for('pets'))

@app.route('/animal/<int:animal_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_pet(animal_id):
    animal = Animal.query.get_or_404(animal_id)

    if not current_user.is_volunteer:
        abort(403)  # Acesso não autorizado

    form = AddPetForm(obj=animal)

    if form.validate_on_submit():
        form.populate_obj(animal)
        db.session.commit()
        flash('Informações do animal atualizadas com sucesso!', 'success')
        return redirect(url_for('pet_details', animal_id=animal.id))

    return render_template('edit_pet.html', form=form, animal=animal)

@app.route('/adoption')
@login_required
def adoption():
    if current_user.is_volunteer:
        flash('Acesso não autorizado. Esta página é destinada apenas para adotantes.', 'danger')
        return redirect(url_for('profile'))

    dogs = Animal.query.filter_by(species='Cachorro').all()
    cats = Animal.query.filter_by(species='Gato').all()

    return render_template('adoption.html', dogs=dogs, cats=cats)

@app.route('/adoption/conhecer_<int:animal_id>', methods=['GET', 'POST'])
@login_required
def conhecer_pet(animal_id):
    if current_user.is_volunteer:
        flash('Apenas adotantes podem acessar esta rota.', 'danger')
        return redirect(url_for('adoption'))

    animal = Animal.query.get(animal_id)
    if not animal:
        flash('Animal não encontrado.', 'danger')
        return redirect(url_for('adoption'))

    if request.method == 'POST':
        # Iniciar o processo de adoção
        adocao = AdoptionProcess(user_id=current_user.id, animal_id=animal_id, status='Em andamento', kit_cuidados=False)
        db.session.add(adocao)
        db.session.commit()

        flash('Você iniciou o processo de adoção!', 'success')

        return redirect(url_for('meus_processos'))  # Redireciona para a página de meus processos

    return render_template('conhecer_pet.html', animal=animal)

@app.route('/adoption/meus_processos', methods=['GET'])
@login_required
def meus_processos():
    if current_user.is_volunteer:
        flash('Apenas adotantes podem acessar esta página.', 'danger')
        return redirect(url_for('adoption'))

    processos = AdoptionProcess.query.filter_by(user_id=current_user.id).all()

    return render_template('meus_processos.html', processos=processos)


@app.route('/adoption/meus_processos/editar_<int:adoption_id>', methods=['GET', 'POST'])
@login_required
def editar_processo(adoption_id):
    if current_user.is_volunteer:
            flash('Apenas adotantes podem acessar esta página.', 'danger')
            return redirect(url_for('adoption'))
  
    processo = AdoptionProcess.query.get_or_404(adoption_id)

    if request.method == 'POST':
        # Atualize o valor de kit_cuidados com base nos dados do formulário
        kit_cuidados = request.form.get('kit_cuidados', False)
        processo.kit_cuidados = (kit_cuidados == 'Sim')

        db.session.commit()
        flash('Processo de adoção atualizado com sucesso.', 'success')
        return redirect(url_for('meus_processos'))

    return render_template('editar_processo.html', processo=processo)

@app.route('/adoption/meus_processos/excluir_<int:adoption_id>', methods=['POST'])
@login_required
def excluir_processo(adoption_id):
    if current_user.is_volunteer:
        flash('Apenas adotantes podem acessar esta página.', 'danger')
        return redirect(url_for('adoption'))
    
    processo = AdoptionProcess.query.get_or_404(adoption_id)

    if request.method == 'POST':
        # Realiza a exclusão do processo de adoção
        db.session.delete(processo)
        db.session.commit()

        flash('Processo de adoção excluído com sucesso!', 'success')
        return redirect(url_for('meus_processos'))

    return redirect(url_for('meus_processos'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)