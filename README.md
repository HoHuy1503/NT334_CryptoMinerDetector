# CryptoMinerDetector

Công cụ giám sát tiến trình và kết nối mạng trên Windows, nhằm nhận diện các dấu hiệu có thể liên quan đến hoạt động đào tiền mã hóa trái phép.

## Chức năng

- Ghi nhận tiến trình, mức sử dụng CPU và kết nối mạng theo chu kỳ.
- Theo dõi hoạt động CPU và GPU theo tiến trình qua nhiều mẫu; tải GPU kéo dài chỉ là một dấu hiệu hỗ trợ vì game và ứng dụng đồ họa cũng dùng GPU.
- Phát hiện bằng các quy tắc có giải thích: tên miner đã biết, URI mining pool trong command line, cổng thường dùng bởi mining pool, CPU cao kéo dài, đường dẫn thực thi đáng ngờ và kết nối công khai kéo dài.
- Ghi snapshot và cảnh báo theo định dạng JSON Lines để xem lại.
- Với command line, chương trình chỉ lưu mã dấu hiệu phù hợp, không ghi toàn bộ tham số có thể chứa bí mật.
- Tra cứu tùy chọn MalwareBazaar bằng SHA-256 của tệp thực thi đáng ngờ. Chương trình chỉ gửi mã hash, không tải tệp lên.
- Chỉ cảnh báo; chương trình không tự dừng hoặc xóa tiến trình.

Cảnh báo là dấu hiệu cần kiểm tra thêm, không phải kết luận chắc chắn máy đã nhiễm miner. Kết quả MalwareBazaar cho biết danh tiếng mã độc của tệp, nhưng không tự khẳng định tệp đang đào tiền mã hóa.

## Yêu cầu

- Windows
- Python 3.10 trở lên
- Thư viện `psutil`

## Cài đặt và chạy

Mở CMD tại thư mục dự án:

```cmd
py -m venv .venv
.venv\Scripts\activate
pip install psutil
python main.py
```

Mở giao diện desktop bằng `python ui.py`.

Dừng chương trình bằng `Ctrl+C`.

## Ghi và phân tích lưu lượng PCAP

Cài Wireshark cùng Npcap (có TShark và Dumpcap), và đưa Java vào PATH. Đặt hai tệp wekaready_miners.csv và wekaready_notminers.csv từ [WEKA-CSV của NESFIT](https://github.com/nesfit/DI-cryptominingdetection/tree/master/WEKA-CSV) trong weka-data. Đặt [Weka 3.8.6](https://repo.maven.apache.org/maven2/nz/ac/waikato/cms/weka/weka-stable/3.8.6/weka-stable-3.8.6.jar) và [Bounce 0.18](https://repo.maven.apache.org/maven2/nz/ac/waikato/cms/weka/thirdparty/bounce/0.18/bounce-0.18.jar) trong weka-jars ở thư mục dự án.

~~~cmd
if not exist data mkdir data
.venv\Scripts\python.exe mining_model.py train weka-data weka-jars data\traffic.model
.venv\Scripts\python.exe ui.py
~~~

Trong **Giám sát**, chọn card mạng rồi bấm **Bắt đầu giám sát**. Khi bấm **Dừng**, ứng dụng kết thúc lấy mẫu tiến trình trước bước phân tích J48. Bản ghi và kết quả nhúng nằm trong data/pcaps. Xem kết quả trong **Kết quả → Lưu lượng PCAP**, hoặc dùng **Mở PCAP** với bản ghi có sẵn. Trong Wireshark, mở **Statistics → Capture File Properties → Comments** để đọc kết quả nhúng.

Chọn một dòng để xem tám đặc trưng, TCP stream, tên miền TLS/HTTP quan sát được và PID ứng viên nếu ghép được với snapshot cùng phiên. Nhãn J48 được dùng để ưu tiên kiểm tra. PCAP và mô hình được tạo cục bộ trong data/.

## Tra cứu MalwareBazaar (tùy chọn)

Đặt khóa API trong phiên CMD hiện tại trước khi chạy chương trình:

```cmd
set MALWAREBAZAAR_AUTH_KEY=YOUR_API_KEY
python main.py
```

Mở giao diện desktop bằng `python ui.py`.

Thay `YOUR_API_KEY` bằng khóa của bạn. Không ghi khóa API vào mã nguồn hoặc commit khóa lên GitHub. Nếu không đặt biến này, chương trình vẫn chạy bộ phát hiện cục bộ.

## Công cụ hỗ trợ

Xem lại nhật ký:

```cmd
python review_logs.py
```

Xem tiến trình theo PID trong snapshot mới nhất:

```cmd
python inspect_pid.py 1234
```

Thay `1234` bằng PID cần kiểm tra. Thông tin hiển thị từ snapshot là dữ liệu lịch sử tại thời điểm thu thập.

## Kiểm tra

```cmd
python -m unittest -v test_rule_engine.py
```

## Dữ liệu và riêng tư

Nhật ký hệ thống được lưu trong thư mục `data/` và có thể chứa tên máy, PID, tên tiến trình, đường dẫn tệp và địa chỉ mạng. Không công khai nhật ký thật hoặc khóa API. Thư mục dữ liệu, môi trường ảo, tệp `.env` và tệp khóa cần được loại khỏi Git.
