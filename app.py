from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from config import Config
from flasgger import Swagger, swag_from
import bcrypt
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity,
)

app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
jwt = JWTManager(app)
Swagger(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)


class Recipe(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    ingredients = db.Column(db.Text, nullable=False)
    time_minutes = db.Column(db.Integer, nullable=False)


@app.route("/register", methods=["POST"])
@swag_from("swagger_docs/register_user.yml")
def register_user():
    data = request.get_json()

    if User.query.filter_by(username=data["username"]).first():
        return jsonify({"error": "User already exists"}), 400
    password = b"data['password']"
    salt = bcrypt.gensalt()
    hashed_pw = bcrypt.hashpw(password=password, salt=salt)
    new_user = User(username=data["username"], password=hashed_pw)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"msg": "User created"}), 201


@app.route("/login", methods=["POST"])
@swag_from("swagger_docs/login.yml")
def login():
    data = request.get_json()
    password = b"data['password']"
    user = User.query.filter_by(username=data["username"]).first()
    if user and bcrypt.checkpw(password, user.password):
        # Converter o ID para string
        token = create_access_token(identity=str(user.id))
        return jsonify({"access_token": token}), 200
    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    current_user_id = (
        get_jwt_identity()
    )  # retorna o 'identity' usado na criação do token
    return (
        jsonify({"msg": f"Usuário com ID {current_user_id} acessou a rota protegida."}),
        200,
    )


@app.route("/recipes", methods=["POST"])
@jwt_required()
@swag_from("swagger_docs/create_recipe.yml")
def create_recipe():

    data = request.get_json()
    new_recipe = Recipe(
        title=data["title"],
        ingredients=data["ingredients"],
        time_minutes=data["time_minutes"],
    )
    db.session.add(new_recipe)
    db.session.commit()
    return jsonify({"msg": "Recipe created"}), 201


@app.route("/recipes", methods=["GET"])
@jwt_required()
@swag_from("swagger_docs/get_recipes.yml")
def get_recipes():

    ingredient = request.args.get("ingredient")
    max_time = request.args.get("max_time", type=int)

    query = Recipe.query
    if ingredient:
        query = query.filter(Recipe.ingredients.ilike(f"%{ingredient}%"))
    if max_time:
        query = query.filter(Recipe.time_minutes <= max_time)

    recipes = query.all()
    return jsonify(
        [
            {
                "id": r.id,
                "title": r.title,
                "ingredients": r.ingredients,
                "time_minutes": r.time_minutes,
            }
            for r in recipes
        ]
    )


@app.route("/recipes/<int:recipe_id>", methods=["PUT"])
@jwt_required()
@swag_from("swagger_docs/update_recipe.yml")
def update_recipe(recipe_id):

    data = request.get_json()
    recipe = Recipe.query.get_or_404(recipe_id)
    if "title" in data:
        recipe.title = data["title"]
    if "ingredients" in data:
        recipe.ingredients = data["ingredients"]
    if "time_minutes" in data:
        recipe.time_minutes = data["time_minutes"]

    db.session.commit()
    return jsonify({"msg": "Recipe updated"}), 200


@app.route("/recipes/<int:recipe_id>", methods=["DELETE"])
@jwt_required()
@swag_from("swagger_docs/delete_recipe.yml")
def delete_recipe(recipe_id):

    recipe = Recipe.query.get_or_404(recipe_id)

    db.session.delete(recipe)
    db.session.commit()
    return jsonify({"msg": "Recipe deleted"}), 200


if __name__ == "__main__":
    app.run(debug=True)
