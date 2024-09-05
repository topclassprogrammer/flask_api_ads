# Примеры REST API-запросов

import requests

# Создать пользователя с получением токена
req = requests.post(
    'http://127.0.0.1:5000/user',
    json={'first_name': 'Jason', 'last_name': 'Statham',
          'email': 'jason777@gmail.com', 'password': 'jas0n_ST!@#'})


# Получить информацию об аккаунте пользователя
# req = requests.get('http://127.0.0.1:5000/user/2')


# Изменить информацию в аккаунте пользователя
# req = requests.patch(
#     'http://127.0.0.1:5000/user/1',
#     json={'first_name': 'David'},
#     headers={'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTcyNTQ2ODEzMSwianRpIjoiZTVkN2EyOTItODAwYi00NzlmLTkyNjctOTZlZDg0OWEwZGY0IiwidHlwZSI6ImFjY2VzcyIsInN1YiI6MSwibmJmIjoxNzI1NDY4MTMxLCJjc3JmIjoiN2EzMWEzNWUtNTE5YS00ZDUzLWFlMGMtZTFlMWE3NGU3OTU3IiwiZXhwIjoxNzI1NDY5MDMxfQ.WmjNm6AboEmNbnTcOFO3xCwREBiNVmh9lnefbsE7PLc'})


# Удалить аккаунт пользователя
# req = requests.delete(
#     'http://127.0.0.1:5000/user/3',
#     headers={'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTcyNTQ2ODE4MywianRpIjoiYTA0MGY5ZTYtNmYwNC00YzUwLWJlYzctYzdjY2UzYzU2ZDI3IiwidHlwZSI6ImFjY2VzcyIsInN1YiI6MywibmJmIjoxNzI1NDY4MTgzLCJjc3JmIjoiNDhmMTgzYjAtM2YwYi00Yzg5LTg0OGUtZmQ1MjExYmIxZTM1IiwiZXhwIjoxNzI1NDY5MDgzfQ.PwBee78g7wjQlI7yGJ0zja_hdlTUhKKxp1HYyPhZWmQ'})


# Создать объявление
# req = requests.post(
#     'http://127.0.0.1:5000/advert',
#     json={'title': 'Продаю телефон', 'description': 'iPhone 15 Pro 256Гб белый в хорошем состоянии', 'owner': '1'},
#     headers={'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTcyNTQ2ODEzMSwianRpIjoiZTVkN2EyOTItODAwYi00NzlmLTkyNjctOTZlZDg0OWEwZGY0IiwidHlwZSI6ImFjY2VzcyIsInN1YiI6MSwibmJmIjoxNzI1NDY4MTMxLCJjc3JmIjoiN2EzMWEzNWUtNTE5YS00ZDUzLWFlMGMtZTFlMWE3NGU3OTU3IiwiZXhwIjoxNzI1NDY5MDMxfQ.WmjNm6AboEmNbnTcOFO3xCwREBiNVmh9lnefbsE7PLc'})


# Получить объявление
# req = requests.get('http://127.0.0.1:5000/advert/1')


# Изменить объявление
# req = requests.patch(
#     'http://127.0.0.1:5000/advert/1',
#     json={'description': 'Samsung Galaxy S24 512Гб'},
#     headers={'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTcyNTQ2ODEzMSwianRpIjoiZTVkN2EyOTItODAwYi00NzlmLTkyNjctOTZlZDg0OWEwZGY0IiwidHlwZSI6ImFjY2VzcyIsInN1YiI6MSwibmJmIjoxNzI1NDY4MTMxLCJjc3JmIjoiN2EzMWEzNWUtNTE5YS00ZDUzLWFlMGMtZTFlMWE3NGU3OTU3IiwiZXhwIjoxNzI1NDY5MDMxfQ.WmjNm6AboEmNbnTcOFO3xCwREBiNVmh9lnefbsE7PLc'})


# Удалить объявление
# req = requests.delete(
#     'http://127.0.0.1:5000/advert/1',
#     headers={'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTcyNTQ2ODEzMSwianRpIjoiZTVkN2EyOTItODAwYi00NzlmLTkyNjctOTZlZDg0OWEwZGY0IiwidHlwZSI6ImFjY2VzcyIsInN1YiI6MSwibmJmIjoxNzI1NDY4MTMxLCJjc3JmIjoiN2EzMWEzNWUtNTE5YS00ZDUzLWFlMGMtZTFlMWE3NGU3OTU3IiwiZXhwIjoxNzI1NDY5MDMxfQ.WmjNm6AboEmNbnTcOFO3xCwREBiNVmh9lnefbsE7PLc'})


# print(req.status_code)
# print(req.json())
