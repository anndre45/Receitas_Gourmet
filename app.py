from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from config import Config
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity
)

app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
jwt = JWTManager(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

class Recipe(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    ingredients = db.Column(db.Text, nullable=False)
    time_minutes = db.Column(db.Integer, nullable=False)

@app.route('/register', methods=['POST'])
def register_user():
    """
    Registra um novo usuário.
    ---
    parameters:
    - in: body
        name: body
        required: true
        schema:
            type: object
            properties:
                username:
                    type: string
                password:
                    type: string
    responses:
        201:
            description: Usuário criado com sucesso.
        400:
            description: Usuário já existe
    """

    data = request.get_json()
    if User.query.filter_by(username=data['username']).first():
        return jsonify({"error": "User already exists"}), 400
    new_user = User(username=data['username'], password=data['password'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"msg": "User created"}), 201

@app.route('/login', methods=['POST'])
def login():
    """
    Faz o login do usuário e retorna um JWT.
    ---
    parameters:
    - in: body
        name: body
        required: true
        schema:
            type: object
            properties:
                username:
                    type: string
                password:
                    type: string
    responses;
        200:
            description: Login bem sucedido, retorna JWT
        401:
            description: Credenciais inválidas
    """
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user and user.password == data['password']:
        #Converter o ID para string
        token = create_access_token(identity=str(user.id))
        return jsonify({"access_token": token}), 200
    return jsonify({"error": "Invalid credentials"}), 401

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user_id = get_jwt_identity() #retorna o 'identity' usado na criação do token
    return jsonify({"msg": f"Usuário com ID {current_user_id} acessou a rota protegida."}), 200

@app.route('/recipes', methods=['POST'])
@jwt_required()
def create_recipe():
    """
    Cria uma nova receita.
    ---
    security:
        - BearerAuth: []
    parameters:
        - in: body
            name: body
            schema:
                type: object
                required: true
                properties:
                    title:
                        type: string
                    ingredients:
                        type: string
                    time_minutes:
                        type: integer
    responses:
        201:
            description: Receita criada com sucesso
        401:
            description: Token não fornecido ou inválido
    """
    data = request.get_json()
    new_recipe = Recipe(
        title= data['title'],
        ingredients = data['ingredients'],
        time_minutes= data['time_minutes']
    )
    db.session.add(new_recipe)
    db.session.commit()
    return jsonify({"msg": "Recipe created"}), 201


@app.route('/recipes', methods=['GET'])
@jwt_required()
def get_recipes():
    """
    Lista receitas com filtros opcionais.
    ---
    security:
        - BearerAuth: []
    parameters:
        - in: query
            name: ingredient
            type: string
            required: false
            description: Filtra por ingrediente
        - in: query
            name: max_time
            type: integer
            required: false
            description: Tempo máximo de preparo (minutos)
    responses:
        200:
            description: Lista de Receitas filtradas
            schema:
                type: array
                items:
                    type: object
                    properties:
                        id:
                            type: integer
                        title:
                            type: string
                        time_minutes:
                            type: integer
    """
    ingredient = request.args.get('ingredient')
    max_time = request.args.get('max_time', type=int)

    query = Recipe.query
    if ingredient:
        query = query.filter(Recipe.ingredients.ilike(f"%{ingredient}%"))
    if max_time:
        query = query. filter(Recipe.time_minutes <= max_time)

    recipes = query.all()
    return jsonify([
        {
            "id": r.id,
            "title": r.title,
            "ingredients": r.ingredients,
            "time_minutes": r.time_minutes
        }
        for r in recipes
    ])




if __name__ == '__main__':
    app.run(debug=True)