from flask import Flask, jsonify, request
from db import get_db
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
     JWTManager,
     create_access_token,
     jwt_required,
     get_jwt_identity
)

from config import config




app = Flask(__name__)

app.config["JWT_SECRET_KEY"] = config.JWT_SECRET_KEY

bcrypt = Bcrypt(app)
jwt = JWTManager(app)

#--------------Register--------------

@app.route("/register",methods=["POST"])
def register():
     data = request.get_json()

     if not data or "name" not in data or "email" not in data or "password" not in data:
          return jsonify ({"error":"All fields are required"}),400
     
     db = get_db()
     cursor = db.cursor(dictionary=True)
     cursor.execute("SELECT * FROM users  WHERE email = %s",(data["email"],))
     existing_user = cursor.fetchone()

     if existing_user:
          return jsonify({"email":"Email already exist"}),400
     
     hashed_password = bcrypt.generate_password_hash(data["password"]).decode("utf-8")


     cursor.execute("INSERT INTO users (name, email, password) VALUES(%s, %s, %s)",(data["name"], data["email"], hashed_password))

     db.commit()
     cursor.close()
     db.close()

     return jsonify({"message":"User registered successfully"}),201

#-------------------------Login--------------

@app.route("/login",methods=["POST"])
def login():

     data = request.get_json()

     db = get_db()
     cursor = db.cursor(dictionary=True)

     cursor.execute("SELECT * FROM users WHERE email = %s", (data["email"],))
     user = cursor.fetchone()

     if not user or not bcrypt.check_password_hash(user["password"], data["password"]):

          return jsonify({"error":"Invalid credentials"}),401
     
     access_token=create_access_token(identity= str(user["id"]))

     cursor.close()
     db.close()


     return jsonify({"access_token":access_token}),200

#---------------Protect route--------------

@app.route("/protected",methods=["GET"])
@jwt_required()
def protected():
     current_user= get_jwt_identity()
     return jsonify({"message":f"Logged in user ID:{current_user}"}),200


     


#--------GET ALL---------------

@app.route("/products",methods=["GET"])
@jwt_required()
def get_products():
     try:
          current_user_id = int(get_jwt_identity())
          db = get_db()
          cursor = db.cursor(dictionary=True)

          cursor.execute("SELECT * FROM products WHERE user_id=%s",(current_user_id,))
          data= cursor.fetchall()

          cursor.close()
          db.close()

          return jsonify(data),200
     except Exception as e:
          return jsonify({"error":str(e)}),500
     

#------GET SINGALE--------

@app.route("/products/<int:product_id>",methods=["GET"])
@jwt_required()
def single_product(product_id):
     try:
          current_user_id= int(get_jwt_identity())
          db = get_db()
          cursor = db.cursor(dictionary=True)
          cursor.execute("SELECT * FROM products where id = %s and user_id= %s",(product_id, current_user_id))
          product = cursor.fetchone()

          cursor.close()
          db.close()

          if not product:
               return jsonify ({"error":"Product not found or unauthorized"}),404
          
          return jsonify(product),200
     

     except Exception as e:
          return jsonify ({"error":str(e)}), 500

#----------POST---------------    

@app.route("/products",methods=["POST"])
@jwt_required()
def add_product():
     current_user_id = int(get_jwt_identity())
     data = request.get_json()

     if not data or "name"  not in data or "price" not in data:
          return jsonify ({"error":"name and price required"}),404
     
     try:
          db = get_db()
          cursor = db.cursor()
          data = request.get_json()

          query = "INSERT INTO products(name, price, user_id) VALUES (%s, %s, %s)"
          valus = (data["name"], data["price"], current_user_id)
          cursor.execute(query, valus)
          db.commit()
          cursor.close
          db.close

          return jsonify ({"message":"product created"}),201
     except Exception as e:
          return jsonify({"error":str(e)}),500
     
#-----------------UPDATE----------------------

@app.route("/products/<int:product_id>",methods=["PUT"])
@jwt_required()
def update_product(product_id):

     current_user_id = int(get_jwt_identity())
     data = request.get_json()

     if not data:
          return jsonify ({"error":"data not provided"}),400
     
     try:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        # Check existence
        cursor.execute("SELECT * FROM products WHERE id = %s and user_id= %s ",(product_id, current_user_id))
        product = cursor.fetchone()

        if not product:
             cursor.close()
             db.close()
             return jsonify ({"error":"Product not found or unauthorized"}),404
        

        # Check existence
        new_name = data.get("name", product["name"])
        new_price = data.get("price", product["price"])


        cursor.execute("UPDATE products set name= %s, price=%s where id = %s",(new_name, new_price,product_id))

        db.commit()
        cursor.close()
        db.close()

        return jsonify({"message":"product updated"}),200
     
     except Exception as e:
          return jsonify({"error":str(e)}),500
     
# ---------------- DELETE ----------------

@app.route("/products/<int:product_id>",methods=["DELETE"])
@jwt_required()
def delete_product(product_id):
     
     try:
          current_user_id = int(get_jwt_identity())

          db = get_db()
          cursor = db.cursor()

          cursor.execute("DELETE FROM products WHERE id = %s and user_id= %s",(product_id,current_user_id))
          db.commit()

          if cursor.rowcount == 0:
               cursor.close()
               db.close()

               return jsonify({"error":"Product not found or unauthorized"}),404
          
          cursor.close()
          db.close()
          return jsonify({"message":"Product deleted"}),201
     except Exception as e:
          return jsonify({"error":str(e)}),500


if __name__ == "__main__":
     app.run(debug=True)





     

     




