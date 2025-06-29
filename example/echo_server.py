import socket  # 소켓 통신을 위한 표준 라이브러리

HOST = '127.0.0.1'  # 서버 IP 주소
PORT = 12345        # 사용할 포트 번호

# 1. 서버 소켓 생성 (IPv4, TCP)
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# 2. 소켓에 주소와 포트 바인딩
server_socket.bind((HOST, PORT))

# 3. 연결 대기 시작
server_socket.listen()
print(f"서버가 {HOST}:{PORT} 에서 대기 중입니다...")

# 4. 여러 클라이언트를 순차적으로 처리하는 루프
while True:
   # 5. 클라이언트 연결 수락
   client_socket, client_address = server_socket.accept()
   print(f"클라이언트 연결됨")

   # 6. 해당 클라이언트와의 통신 루프
   while True:
       data = client_socket.recv(1024)

       # 클라이언트가 연결을 끊은 경우
       if not data:
           print(f"클라이언트 종료됨: {client_address}")
           break

       print("받은 메시지:", data.decode())
       client_socket.sendall(data)

   # 7. 해당 클라이언트 소켓 닫기
   client_socket.close()
