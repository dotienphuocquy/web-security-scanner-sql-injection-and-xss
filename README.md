# Cách sử dụng nhanh:
## 1. Cài đặt dependencies:

   pip install -r requirements.txt

## 2. Test với vulnerable app:

  ### Terminal 1: Chạy vulnerable app
  cd vulnerable_app
  python app.py
  
  ### Terminal 2: Scan
  python main.py -u http://127.0.0.1:8080/login -t all

## 3. Hoặc dùng Web GUI:

  python main.py --gui
  # Truy cập: http://127.0.0.1:5000
