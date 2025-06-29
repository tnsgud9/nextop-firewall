import socket  # 소켓 통신을 위한 표준 라이브러리

HOST = '127.0.0.1'  # 연결할 서버 IP 주소
PORT = 12345        # 연결할 서버 포트 번호

# 1. 소켓 생성 (IPv4, TCP)
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# 2. 서버에 연결 요청
client_socket.connect((HOST, PORT))
print(f"{HOST}:{PORT} 서버에 연결되었습니다.")


# 3. 메시지 송수신 루프
while True:
   # 4. 사용자 입력 받기
   message = input("메시지 입력 (exit 입력 시 종료): ")

   # 5. 아무 것도 입력하지 않으면 무시하고 다시 입력
   if message.strip() == "":
       continue

   # 6. 'exit' 입력 시 종료
   if message == "exit":
       break

   # 7. 서버에 메시지 전송
   client_socket.sendall(message.encode())

   # 8. 서버로부터 응답 수신
   data = client_socket.recv(1024)

   # 9. 수신 데이터 출력
   print("서버 응답:", data.decode())

# 10. 소켓 닫기
client_socket.close()


