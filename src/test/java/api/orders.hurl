# On appelle l'endpoint GET
GET http://host.docker.internal:8080/api/orders

# Vérification du code retour
HTTP 200

[Asserts]
# On vérifie que c'est bien une liste de 2 éléments
jsonpath "$" count == 2

# Vérification du premier élément (Laptop)
jsonpath "$[0].id" == 1
jsonpath "$[0].product" == "Laptop"
jsonpath "$[0].price" == 1200.0

# Vérification du deuxième élément (Mouse)
jsonpath "$[1].id" == 2
jsonpath "$[1].product" == "Mouse"
jsonpath "$[1].price" == 25.0