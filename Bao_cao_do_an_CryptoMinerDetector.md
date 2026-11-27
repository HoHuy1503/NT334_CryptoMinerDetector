# BÁO CÁO ĐỒ ÁN NT334
# CryptoMinerDetector — Phát hiện hoạt động đào tiền mã hóa bằng phân tích lưu lượng mạng

**Ngày lập báo cáo** 27/11/2026\
**Phiên bản khảo sát** [Mã nguồn tại commit da8087b](https://github.com/HoHuy1503/NT334_CryptoMinerDetector/tree/da8087b)\
**Nền tảng triển khai** Windows, Python, psutil, Tkinter và bộ đếm hiệu năng GPU của Windows.

## Tóm tắt và mục tiêu nghiên cứu

Đồ án triển khai hai phần. Phần chính đánh giá khả năng phát hiện giao tiếp đào tiền mã hóa từ thống kê luồng TCP theo nghiên cứu của Veselý và Žádník. Phần bổ trợ dùng quan sát tại máy Windows để điều tra tiến trình và tệp thực thi. Phiên bản GitHub nêu trên là mốc của phần Windows. Mô-đun phân tích lưu lượng được bổ sung trong bản làm việc ngày 27/11/2026.

### Phương pháp của công trình tham khảo

Tác giả gom luồng theo bộ ba **IP nguồn, IP đích và cổng đích**. Một mẫu phân loại đại diện cho hành vi giao tiếp quan sát được của bộ ba. Phương pháp kết hợp phân loại thụ động, xác minh dịch vụ và danh mục máy chủ mining pool sMaSheD. Kho dữ liệu gồm PCAP phục vụ nghiên cứu, cấu hình CGMiner, danh mục lịch sử và hai bộ vector có nhãn. Đồ án tái hiện nhánh phân loại thụ động từ các vector công bố. [Bản thảo của tác giả](https://github.com/nesfit/DI-cryptominingdetection/blob/master/article/elsarticle-template.tex) · [Dữ liệu NESFIT](https://github.com/nesfit/DI-cryptominingdetection)

### Đặc trưng lưu lượng

| Cột trong vector | Đại lượng quan sát |
|---|---|
| ackpush/all | Tỷ lệ flow mang tổ hợp cờ ACK và PUSH |
| bpp | Số byte trên gói tính từ thống kê flow |
| ppf | Số gói trên flow |
| ppm | Số gói trên phút |
| req/all | Tỷ lệ flow có cổng nguồn lớn hơn cổng đích, dùng để xấp xỉ hướng yêu cầu |
| syn/all, rst/all, fin/all | Ba tỷ lệ riêng ứng với flow mang cờ SYN, RST và FIN |

Các đặc trưng mô tả kích thước, nhịp trao đổi và trạng thái kết nối. Chúng cho phép phân loại khi chỉ có số liệu luồng. Nhãn ở cột thứ chín là miner hoặc notminer. Mã phân tích giữ nguyên thang đo trong CSV của tác giả.

### Triển khai và tái lập trên Windows CMD

Mô-đun **traffic_forensics.py** kiểm tra cấu trúc và nhãn của hai CSV, chuyển dữ liệu sang ARFF rồi gọi Weka 3.8.6. J48 được cấu hình với số instance tối thiểu ở lá là 100. Bộ lọc ClassBalancer cân bằng trọng số hai lớp trên phần huấn luyện trong từng fold. Đồ án dùng kiểm định chéo phân tầng 5 fold với seed 1 và đánh giá dự đoán trên các mẫu được giữ lại.

Để chạy lại, đặt hai tệp từ [WEKA-CSV](https://github.com/nesfit/DI-cryptominingdetection/tree/master/WEKA-CSV) vào thư mục weka-data. Đặt [weka-stable-3.8.6.jar](https://repo.maven.apache.org/maven2/nz/ac/waikato/cms/weka/weka-stable/3.8.6/weka-stable-3.8.6.jar) và [bounce-0.18.jar](https://repo.maven.apache.org/maven2/nz/ac/waikato/cms/weka/thirdparty/bounce/0.18/bounce-0.18.jar) vào weka-jars. Khi Java và Python đã có trong PATH, chạy tại thư mục dự án:

~~~cmd
python traffic_forensics.py weka-data weka-jars
~~~

### Kết quả thực nghiệm trên 356.847 vector

| Nhãn thực | Dự đoán miner | Dự đoán notminer |
|---|---:|---:|
| miner | 246 | 27 |
| notminer | 1.849 | 354.725 |

Mô hình phát hiện 246 trong 273 mẫu miner, đạt **recall 90,11%**. Trong 2.095 mẫu bị gắn cờ, 246 mẫu thật sự mang nhãn miner, cho **precision 11,74%** và F1 xấp xỉ 0,208. Tỷ lệ báo động sai trên lớp âm là 0,52%. Accuracy chung đạt 99,47%. Do lớp miner rất hiếm, dự đoán toàn bộ là notminer cũng đạt khoảng 99,92% accuracy dù bỏ sót mọi mẫu dương. Khi đánh giá khả năng hỗ trợ điều tra cần đọc cả ma trận nhầm lẫn.

Bản thảo báo cáo khoảng 4,7% mẫu miner bị bỏ sót và 2,6% mẫu khác bị gắn nhầm trong thực nghiệm của tác giả. Trong lần chạy của đồ án, tỷ lệ bỏ sót là 9,89%. Phiên bản phần mềm, cách chia fold và áp dụng trọng số là các yếu tố cần kiểm soát trước khi giải thích chênh lệch. Kết quả hiện tại phản ánh phân loại vector có sẵn trên bộ dữ liệu lịch sử. Đánh giá trên một mạng độc lập và dữ liệu mới hơn vẫn cần thiết.

### Quan hệ với ứng dụng Windows

Ứng dụng thu gói trên card mạng đã chọn và lấy mẫu tiến trình trong cùng phiên. Khi dừng, bộ quét tiến trình thoát trước khi phân tích J48. TShark đọc PCAPNG, dựng flow có hướng và tổng hợp tám đặc trưng. Ứng dụng hiển thị dự đoán ở tab Lưu lượng PCAP và nhúng kết quả vào phần bình luận của bản ghi. Có thể mở PCAP đã thu để phân tích ngoại tuyến.

Bằng chứng gồm TCP stream liên kết hai chiều, SYN đầu tiên nếu quan sát được, tên miền từ TLS SNI hoặc HTTP Host và PID ứng viên khớp IP/cổng trong snapshot cùng phiên. Với nội dung đọc được, công cụ ghi nhận mining.notify và mining.submit ở hai chiều. Ví dụ, stream 109 trong một phiên cục bộ mang tên miền entitlements.auth.riotgames.com dù J48 gắn cờ chiều phản hồi. Tên miền và PID bổ sung ngữ cảnh xác minh.

### So sánh trọng số J48

| Trọng số | Phát hiện miner | Bỏ sót | Báo nhầm | Recall | Precision |
|---|---:|---:|---:|---:|---:|
| Gốc | 109 | 164 | 81 | 39,93% | 57,37% |
| Trung gian | 230 | 43 | 1.146 | 84,25% | 16,72% |
| Cân bằng | 246 | 27 | 1.849 | 90,11% | 11,74% |

Ba cấu hình dùng cùng năm fold NESFIT. Ứng dụng dùng cấu hình cân bằng để ưu tiên recall. Luồng phân tích của UI đã chạy trên cgminer.g0.pcapng và gắn cờ 175 trong 1.148 bộ ba. Đây là số dự đoán, chưa có nhãn đối chứng cho từng bộ ba. Phiên ghi loopback đã xác nhận có thể nhúng dự đoán vào PCAPNG và đọc lại. Hướng dẫn dựng mô hình và chạy ứng dụng nằm trong README.md.

## Phần bổ trợ — Giám sát và truy vết trên máy trạm

CryptoMinerDetector giúp người dùng xác định tiến trình nào cần được kiểm tra khi nghi máy tính bị sử dụng để đào tiền mã hóa. Chương trình lấy mẫu tiến trình và kết nối mạng, đánh giá từng tiến trình theo các quy tắc có giải thích, rồi tổng hợp kết quả theo PID và thời điểm khởi chạy. Mỗi cảnh báo có điểm ưu tiên, các dấu hiệu đã kích hoạt và thông tin truy vết có thể thu được tại thời điểm phát hiện. Người vận hành có thể xem trực tiếp trên giao diện hoặc phân tích nhật ký sau phiên giám sát.

Đồ án đã triển khai được luồng từ thu thập đến hiển thị và lưu bằng chứng. Chín bài kiểm thử tự động đã đạt trên phiên bản được công bố. Phần đánh giá trình bày riêng kết quả kiểm tra logic và những câu hỏi còn mở về độ chính xác trên máy người dùng thực tế.

## 1. Bài toán, mục tiêu và phạm vi

Một máy tính chạy chậm hoặc sử dụng GPU liên tục có thể đang đào tiền mã hóa, chơi game, biên dịch hoặc xử lý đồ họa. Chỉ nhìn phần trăm sử dụng tài nguyên tại một thời điểm khó phân biệt các tình huống này. Ngược lại, chỉ đối chiếu tên tệp có thể bỏ sót phần mềm đã đổi tên.

Đồ án đặt ra ba mục tiêu. Thứ nhất, liên kết mức sử dụng tài nguyên và kết nối mạng với tiến trình cụ thể. Thứ hai, giải thích vì sao tiến trình được ưu tiên kiểm tra. Thứ ba, giữ lại thông tin giúp người dùng tìm tệp và điều tra sau khi cảnh báo xuất hiện. Phạm vi là giám sát cục bộ trên Windows, với quyền truy cập của tài khoản đang chạy ứng dụng. Quyết định cô lập máy hoặc chặn kết nối do người vận hành thực hiện.

## 2. Cơ sở lý thuyết

### 2.1. Đào tiền mã hóa và sử dụng tài nguyên trái phép

Trong các hệ thống dùng cơ chế bằng chứng công việc (Proof of Work), phần mềm đào thực hiện nhiều phép tính để tìm kết quả đáp ứng mục tiêu của thuật toán. Công việc có thể chạy trên CPU hoặc GPU. Khi tham gia một nhóm đào (mining pool), phần mềm nhận công việc và gửi kết quả về máy chủ. Stratum là một họ giao thức thường gặp trong trao đổi này. Việc sử dụng tài nguyên tính toán của người khác để đào khi chưa được cho phép thường được gọi là *cryptojacking*. Sự cho phép của chủ máy là yếu tố mà số liệu CPU, GPU và mạng tự thân không thể xác định.

### 2.2. Từ dấu hiệu nhận dạng đến hành vi

Tên tệp, chuỗi URI Stratum và mã băm là các dấu hiệu nhận dạng. Chúng dễ giải thích nhưng có phạm vi khác nhau. Tên tệp có thể đổi. SHA-256 đại diện cho nội dung của một phiên bản tệp cụ thể. Nếu nội dung thay đổi, kết quả tra cứu mã băm cũ có thể mất giá trị. Phân tích hành vi bổ sung góc nhìn theo thời gian, chẳng hạn cùng tiến trình duy trì tải tính toán và xuất hiện với cùng địa chỉ mạng qua nhiều mẫu.

Trên máy đa lõi, mức CPU của tiến trình theo psutil lấy một lõi logic làm đơn vị 100%, trong khi CPU toàn hệ thống được tính trên toàn bộ lõi. Vì vậy, một tiến trình có thể chiếm gần trọn một lõi khi mức tải chung còn thấp. Với GPU, Windows cung cấp số liệu theo engine, ví dụ 3D hoặc Compute. Loại engine và mức tải cung cấp ngữ cảnh điều tra, nhưng nhiều ứng dụng hợp lệ cũng có cùng hành vi.

### 2.3. Lấy mẫu và quy thuộc bằng chứng

Snapshot là bản ghi trạng thái quan sát được tại một thời điểm. Hai snapshot có cùng PID chưa chắc đại diện cùng tiến trình vì Windows có thể tái sử dụng PID sau khi tiến trình cũ kết thúc. Thời điểm tạo tiến trình, tên và đường dẫn giúp phân biệt các lần chạy. Tương tự, việc quan sát cùng IP trong nhiều mẫu cho thấy sự lặp lại của đầu mạng, chưa chứng minh cùng một phiên TCP mở liên tục hoặc đầu mạng đó điều khiển tiến trình.

## 3. Kiến trúc và luồng triển khai

| Thành phần | Vai trò trong hệ thống |
|---|---|
| `main.py` | Điều phối chu kỳ thu thập, ghép dữ liệu theo PID, gọi bộ phát hiện, ghi nhật ký và gửi sự kiện đến giao diện. |
| `detection/rule_engine.py` | Theo dõi chuỗi mẫu, đánh giá các quy tắc và tạo một cảnh báo tổng hợp cho mỗi tiến trình có dấu hiệu trong snapshot. |
| `detection/threat_intel.py` | Tính SHA-256 và tra cứu MalwareBazaar ở luồng nền khi người dùng cấu hình khóa API. |
| `detection/trace.py` | Thu thập thông tin tệp, nguồn tải nếu còn lưu, tiến trình cha và các kết nối tại lúc cảnh báo. |
| `ui.py` | Cung cấp hai tab Giám sát và Kết quả. Hàng đợi chuyển sự kiện từ luồng giám sát sang giao diện Tkinter. |
| `inspect_pid.py`, `review_logs.py` | Tra cứu PID trong snapshot gần nhất, xem lại nhật ký và xuất báo cáo phiên dạng CSV. |
| `test_rule_engine.py` | Kiểm thử quy tắc và cách xử lý dữ liệu bộ đếm GPU bằng mẫu giả lập. |

Một chu kỳ bắt đầu bằng việc đọc danh sách tiến trình với psutil, gồm PID, PID cha, tên, đường dẫn, thời điểm tạo, CPU và bộ nhớ. Tham số khởi chạy được rà tìm URI Stratum, sau đó chỉ lưu mã dấu hiệu phù hợp. Chương trình lấy danh sách kết nối, đọc bộ đếm GPU Engine qua PowerShell và ghép kết quả với tiến trình. Bộ thu thập GPU nhóm giá trị theo PID và loại engine, giới hạn giá trị nhóm ở 100% rồi lấy nhóm cao nhất. Đây là chỉ số theo cách tổng hợp của ứng dụng và có thể khác giá trị trong Task Manager.

Snapshot được ghi vào `data/system_events.jsonl`. Bộ luật sử dụng snapshot và các bộ đếm trong bộ nhớ để xác định cảnh báo. Mỗi cảnh báo được bổ sung thông tin truy vết và kết quả tra cứu mã băm nếu có, rồi ghi vào `data/alerts.jsonl`. JSON Lines lưu mỗi đối tượng trên một dòng nên có thể đọc tuần tự hoặc xem lại sau phiên. Chu kỳ mục tiêu là 3 giây. Thời gian thực tế phụ thuộc tốc độ thu thập, đặc biệt khi bộ đếm GPU phản hồi chậm.

## 4. Phương pháp phát hiện và tính điểm

| Dấu hiệu | Điều kiện trong phiên bản khảo sát | Điểm |
|---|---|---:|
| Tên miner | So khớp tên đã chuẩn hóa, bỏ phần đường dẫn và đuôi .exe, không phân biệt hoa thường | 60 |
| URI Stratum | Phát hiện tiền tố Stratum được hỗ trợ trong tham số của tiến trình | 40 |
| Cổng mining pool | Đầu xa dùng cổng thuộc danh sách quy tắc, sau khi loại các trạng thái đóng đã định nghĩa | 30 |
| CPU cao kéo dài | CPU tiến trình ≥ 80% trong 5 mẫu liên tiếp | 25 |
| Tiến trình dùng CPU khi tải toàn máy thấp | CPU tiến trình ≥ 20% đồng thời CPU hệ thống ≤ 20% trong 10 mẫu liên tiếp | 20 |
| GPU cao kéo dài | Chỉ số GPU theo tiến trình ≥ 60% trong 10 mẫu liên tiếp | 20 |
| Vị trí tệp cần kiểm tra | Đường dẫn chứa một mẫu thuộc nhóm thư mục tạm, Roaming hoặc thư mục người dùng công cộng | 15 |
| Đầu mạng công khai xuất hiện kéo dài | Cùng tiến trình có kết nối ESTABLISHED tới cùng IP công khai trong 10 mẫu liên tiếp | 15 |
| Mã băm đã được ghi nhận là mã độc | MalwareBazaar trả bản ghi phù hợp cho tệp của một tiến trình đã có cảnh báo | 60 |

Điểm tổng được giới hạn ở 100. Cảnh báo có điểm dưới 25 thuộc mức thấp, từ 25 đến 59 thuộc mức trung bình, từ 60 trở lên thuộc mức cao. Tiến trình không có dấu hiệu sẽ không sinh cảnh báo. Điểm thể hiện thứ tự ưu tiên điều tra. Dự án chưa hiệu chỉnh điểm thành xác suất nhiễm.

Ví dụ, một tiến trình tên xmrig.exe dùng cổng 3333 nhận 60 + 30 = 90 điểm ngay ở mẫu có đủ hai dấu hiệu. Một trò chơi chỉ kích hoạt luật GPU sau 10 mẫu nhận 20 điểm. Nếu một tiến trình tên lạ vừa có URI Stratum vừa duy trì GPU cao, hai luật có thể đưa điểm lên 60 dù tên tiến trình không có trong danh sách. Đây là ví dụ suy ra từ quy tắc.

## 5. Truy vết, giao diện và xử lý cảnh báo

Tab **Giám sát** cung cấp nút bắt đầu, dừng, số tiến trình, kết nối và nhật ký có thời gian. Tab **Kết quả** gộp các sự kiện của cùng một lần chạy tiến trình thành một dòng. Điểm và mức đánh giá cao nhất, số lần xuất hiện, lần đầu, lần gần nhất và tập dấu hiệu giúp người dùng theo dõi diễn biến. Các cột hỗ trợ sắp xếp và giữ thứ tự đã chọn khi có dữ liệu mới.

Người dùng nhấp chuột phải vào kết quả để sao chép tên hoặc mở cửa sổ **Xem truy vết**. Cửa sổ hiển thị bằng chứng của lần cảnh báo gần nhất. Nhấp đúp vào dòng sẽ mở thư mục chứa tệp thực thi nếu đường dẫn cục bộ còn truy cập được.

| Dữ liệu truy vết | Cách diễn giải |
|---|---|
| Đường dẫn, thời điểm tạo tệp, thời điểm tiến trình bắt đầu | Phân biệt tệp trên đĩa với một lần chạy. Sao chép tệp có thể làm thay đổi mốc tạo trên ổ hiện tại. |
| Nguồn tải | Đọc tên máy chủ từ HostUrl trong Zone.Identifier nếu Windows còn lưu. Thiếu trường này thì nguồn tải chưa xác định. |
| PID cha và đường dẫn cha | Cung cấp ngữ cảnh khởi chạy nếu tiến trình cha còn xuất hiện và thời điểm tạo phù hợp. |
| Địa chỉ mạng | Liệt kê đầu xa ở trạng thái ESTABLISHED của PID tại lúc quan sát. Cần thêm bằng chứng để quy thuộc hoạt động từ xa. |

Khi nghi chạy từ xa, người vận hành có thể đối chiếu mốc khởi chạy với sự kiện tạo tiến trình 4688 và phiên đăng nhập 4624 trong nhật ký Security nếu đã bật kiểm toán tương ứng. Bước đối chiếu hiện thực hiện thủ công. Sau khi xác minh, người vận hành có thể cô lập máy hoặc tạo quy tắc Windows Firewall chặn kết nối đi của tệp đã xác định. Chặn kết nối đi vẫn cho phép tiến trình tiếp tục tính toán cục bộ.

## 6. Cài đặt và vận hành

Trong Windows CMD tại thư mục dự án, tạo môi trường và khởi chạy giao diện bằng cùng một trình thông dịch.

```cmd
py -m venv .venv
.venv\Scripts\python.exe -m pip install psutil
.venv\Scripts\python.exe ui.py
```

Chọn **Bắt đầu giám sát** và quan sát qua nhiều chu kỳ. Có thể chạy giao diện dòng lệnh bằng cách thay ui.py bằng main.py. Với tra cứu ngoài, đặt biến môi trường MALWAREBAZAAR_AUTH_KEY trong phiên CMD trước khi chạy. Chương trình chỉ gửi mã SHA-256 và dùng bộ nhớ đệm để giảm truy vấn lặp lại. Nhật ký cục bộ có thể chứa tên người dùng, tên máy, đường dẫn và địa chỉ mạng. Dự án loại thư mục dữ liệu, môi trường ảo và tệp cấu hình bí mật khỏi Git.

## 7. Kiểm thử và kết quả

Lệnh tái hiện bộ kiểm thử là `.venv\Scripts\python.exe -m unittest -v test_rule_engine.py`. Ở lần cập nhật GitHub ngày 26/11/2026, cả **9/9 bài kiểm thử đạt**.

| Nhóm | Số bài | Nội dung đã kiểm tra |
|---|---:|---|
| Tên tiến trình, mạng và Stratum | 4 | Tiến trình bình thường dùng HTTPS, tên miner có đuôi .exe kết hợp cổng pool, kết nối TIME_WAIT và tiến trình tên lạ có dấu hiệu Stratum. |
| Hành vi qua nhiều mẫu | 3 | Thời điểm phát cảnh báo CPU, CPU khi tải hệ thống thấp, GPU kéo dài và việc đặt lại bộ đếm khi chuỗi bị ngắt. |
| Thu thập GPU | 2 | Gom dữ liệu theo PID và loại engine, xử lý khi lệnh đọc bộ đếm thất bại. Dữ liệu được giả lập. |

Trong thử nghiệm tích hợp trước đó, snapshot giả lập có năm dấu hiệu đồng thời đạt 100 điểm. Một truy vấn thử MalwareBazaar với mã băm đã biết trả trạng thái ok và một bản ghi. Phần truy vết được kiểm tra bằng tệp tạm có Zone.Identifier và dữ liệu tiến trình, kết nối giả lập. Kết quả xác nhận đọc được thời điểm tạo tệp, tên miền nguồn và thông tin tương quan. Một lần xem lại nhật ký cũ đọc được 18 snapshot hợp lệ và 0 cảnh báo. Số liệu này thuộc giai đoạn trước khi bổ sung toàn bộ luật hiện tại.

Các lần kiểm tra trên chứng minh các hành vi cụ thể trong điều kiện đã thử. Phần giám sát tiến trình chưa có tập dữ liệu gán nhãn đủ để báo cáo precision, recall hoặc tỷ lệ cảnh báo sai riêng. XMRig benchmark offline đã được đề xuất cho bài thử CPU thực tế. Chưa có số đo từ lần chạy benchmark đó để đưa vào kết quả.

## 8. Hạn chế và hướng phát triển

1. **Cảnh báo sai từ dữ liệu CPU.** Trong một phiên quan sát, System Idle Process (PID 0) xuất hiện với cảnh báo CPU cao. Giá trị này biểu thị thời gian CPU nhàn. Bộ phát hiện hiện loại PID 0. Phép thử hồi quy qua 12 mẫu liên tiếp xác nhận PID 0 không sinh cảnh báo, còn tiến trình thường có CPU cao vẫn được phát hiện. Các tác vụ game, render và biên dịch cũng cần được dùng làm đối chứng.
2. **Độ bao phủ của cảm biến.** Tiến trình tồn tại ngắn có thể kết thúc giữa hai lần lấy mẫu. Quyền truy cập và trình điều khiển GPU ảnh hưởng mức dữ liệu thu được. Mã thực thi bên trong tiến trình hợp lệ có thể chỉ được quy về tiến trình chủ.
3. **Giới hạn của đối chiếu bên ngoài.** Mã băm chưa xuất hiện trong MalwareBazaar vẫn có thể thuộc mẫu mới. Bản ghi mã độc cũng có thể thuộc loại khác ngoài miner. Tra cứu nền cần thời gian, nên kết quả có thể chưa hiện ở cảnh báo đầu tiên.
4. **Đánh giá thực nghiệm.** Nên ghi nhãn từng phiên chạy miner được cho phép và từng tải hợp lệ, đo thời gian tới cảnh báo đầu, tỷ lệ phát hiện theo tiến trình và số cảnh báo sai mỗi giờ. Cần báo cáo riêng trường hợp thiếu dữ liệu GPU và đo chi phí CPU, RAM, dung lượng nhật ký của chính công cụ.
5. **Truy vết sâu hơn.** Có thể bổ sung đọc nhật ký kiểm toán theo quyền của người dùng, gắn nguồn và mức chắc chắn cho từng bằng chứng, đồng thời kiểm soát thời hạn lưu nhật ký.

## 9. Kết luận

CryptoMinerDetector đã hình thành một công cụ Windows có thể chạy bằng CMD hoặc giao diện desktop, kết hợp dấu hiệu nhận dạng với hành vi CPU, GPU và mạng. Kết quả quan trọng của đồ án là khả năng giải thích từng cảnh báo, gộp các lần phát hiện của cùng tiến trình và chuyển từ cảnh báo sang kiểm tra tệp cùng bằng chứng liên quan. Để đánh giá khả năng sử dụng lâu dài, bước tiếp theo là kiểm chứng các ngưỡng trên tập phiên chạy có nhãn.

## Tài liệu tham khảo

1. [Mã nguồn và bộ kiểm thử CryptoMinerDetector](https://github.com/HoHuy1503/NT334_CryptoMinerDetector/tree/da8087b).
2. [Tài liệu psutil về tiến trình, CPU và kết nối mạng](https://psutil.readthedocs.io/en/latest/).
3. [Microsoft Learn — GPU utilization and presentation counters](https://learn.microsoft.com/en-us/windows/win32/direct3dtools/pix/articles/timing-captures/pix-timing-captures).
4. [Microsoft Learn — Windows Security Event 4688](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688) và [Event 4624](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624).
5. [MalwareBazaar API](https://bazaar.abuse.ch/api/).
6. [XMRig — Benchmark](https://xmrig.com/docs/miner/benchmark).
