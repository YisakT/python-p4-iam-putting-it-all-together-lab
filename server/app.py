#!/usr/bin/env python3

from flask import request, session,jsonify
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        data = request.get_json()
        
        # Check if required fields are provided
        if 'username' not in data or 'password' not in data:
            return {'error': 'Both username and password are required.'}, 422
        
        username = data['username']
        password = data['password']
        
        # Check if the username is already taken
        if User.query.filter_by(username=username).first():
            return {'error': 'Username already in use.'}, 422
        
        # Create a new user and save it to the database
        user = User(username=username)
        user.password_hash = password
        
        # Process image_url and bio if provided
        if 'image_url' in data:
            user.image_url = data['image_url']
            
        if 'bio' in data:
            user.bio = data['bio']
        
        try:
            db.session.add(user)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return {'error': 'Error creating user.'}, 422  # Change the status code to 422
        
        # Store the user's ID in the session
        session['user_id'] = user.id
        
        # Return user information
        return {
           'user_id': user.id,
           'username': user.username,
           'image_url': user.image_url,
           'bio': user.bio
        }, 201



class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if user_id:
            user = User.query.get(user_id)
            if user:
                return {
                    'id': user.id,
                    'username': user.username,
                    'image_url': user.image_url,
                    'bio': user.bio
                }, 200
        return {'error': 'Unauthorized'}, 401


class Login(Resource):
    def post(self):
        data = request.json
        username = data.get('username')
        password = data.get('password')

        # Query the database to find the user by username
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            session['user_id'] = user.id
            return {
                'id': user.id,
                'username': user.username,
                'image_url': user.image_url,
                'bio': user.bio
            }, 200
        else:
            return {
                'error': 'Invalid username or password'
            }, 401


class Logout(Resource):
    def delete(self):
        if 'user_id' in session and session['user_id']:
            session['user_id'] = None  # Set user_id to None instead of removing it
            return {}, 204
        else:
            # Return a 401 if the user is not logged in
            return {
                'error': 'Unauthorized: You are not logged in'
            }, 401







class RecipeIndex(Resource):

    def get(self):
        # Check if user is logged in
        if 'user_id' in session and session['user_id']:
            # Fetch all recipes
            recipes = Recipe.query.all()
            
            # Serialize each recipe and add user object
            recipe_list = []
            for recipe in recipes:
                serialized_recipe = {
                    "title": recipe.title,
                    "instructions": recipe.instructions,
                    "minutes_to_complete": recipe.minutes_to_complete,
                    "user": {
                        "id": recipe.user.id,
                        "username": recipe.user.username
                    }
                }
                recipe_list.append(serialized_recipe)
                
            return recipe_list, 200
        else:
            return {"error": "Unauthorized: You need to be logged in to view recipes."}, 401

    def post(self):
        # Check if user is logged in
        if 'user_id' in session and session['user_id']:
            # Get user from the session
            user = User.query.get(session['user_id'])
            
            # Extract data from the request
            data = request.json
            title = data.get('title')
            instructions = data.get('instructions')
            minutes_to_complete = data.get('minutes_to_complete')

            # Additional validation: Check if the title length exceeds a certain limit
            MAX_TITLE_LENGTH = 100 
            if len(title) > MAX_TITLE_LENGTH:
                return {"error": "Title is too long."}, 422

            # Basic validation 
            if not title or not instructions or not minutes_to_complete:
                return {"error": "All fields (title, instructions, and minutes_to_complete) are required."}, 422

            # Create a new Recipe
            new_recipe = Recipe(
                title=title,
                instructions=instructions,
                minutes_to_complete=minutes_to_complete,
                user=user
            )

            try:
                # Save the recipe to the database
                db.session.add(new_recipe)
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                return {"error": "Invalid data provided. Please ensure the data adheres to the database constraints."}, 422

            # Return the newly created recipe with the user details
            return {
                "title": new_recipe.title,
                "instructions": new_recipe.instructions,
                "minutes_to_complete": new_recipe.minutes_to_complete,
                "user": {
                    "id": user.id,
                    "username": user.username
                }
            }, 201
        else:
            return {"error": "Unauthorized: You need to be logged in to create a recipe."}, 401




api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)
