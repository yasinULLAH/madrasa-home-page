<?php
session_start();
$db=new PDO('sqlite:madrasadb.sqlite');
$db->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);
if(!is_dir('uploads')){mkdir('uploads',0755);}
function init_db($db){
$q1="CREATE TABLE IF NOT EXISTS admins(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT UNIQUE,password TEXT,email TEXT,last_login DATETIME)";
$q2="CREATE TABLE IF NOT EXISTS announcements(id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT,body TEXT,priority INTEGER DEFAULT 0,created_at DATETIME DEFAULT CURRENT_TIMESTAMP,updated_at DATETIME,status TEXT DEFAULT 'active')";
$q3="CREATE TABLE IF NOT EXISTS teachers(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT,profile TEXT,img TEXT,position TEXT,qualification TEXT,experience TEXT,email TEXT,phone TEXT,subjects TEXT,status TEXT DEFAULT 'active')";
$q4="CREATE TABLE IF NOT EXISTS courses(id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT,description TEXT,duration TEXT,fee TEXT,instructor_id INTEGER,capacity INTEGER,schedule TEXT,level TEXT,syllabus TEXT,status TEXT DEFAULT 'active')";
$q5="CREATE TABLE IF NOT EXISTS timetable(id INTEGER PRIMARY KEY AUTOINCREMENT,day TEXT,class TEXT,time TEXT,subject TEXT,teacher_id INTEGER,room TEXT)";
$q6="CREATE TABLE IF NOT EXISTS gallery(id INTEGER PRIMARY KEY AUTOINCREMENT,img TEXT,caption TEXT,category TEXT,event_date DATETIME,status TEXT DEFAULT 'active')";
$q7="CREATE TABLE IF NOT EXISTS resources(id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT,file TEXT,description TEXT,category TEXT,size INTEGER,downloads INTEGER DEFAULT 0,date_added DATETIME DEFAULT CURRENT_TIMESTAMP,status TEXT DEFAULT 'active')";
$q8="CREATE TABLE IF NOT EXISTS faqs(id INTEGER PRIMARY KEY AUTOINCREMENT,question TEXT,answer TEXT,category TEXT,display_order INTEGER DEFAULT 0,status TEXT DEFAULT 'active')";
$q9="CREATE TABLE IF NOT EXISTS testimonials(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT,msg TEXT,rating INTEGER,approved INTEGER DEFAULT 0,created_at DATETIME DEFAULT CURRENT_TIMESTAMP)";
$q10="CREATE TABLE IF NOT EXISTS contact(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT,email TEXT,msg TEXT,admin_reply TEXT,status TEXT DEFAULT 'unread',created_at DATETIME DEFAULT CURRENT_TIMESTAMP,replied_at DATETIME)";
$q11="CREATE TABLE IF NOT EXISTS settings(id INTEGER PRIMARY KEY AUTOINCREMENT,setting_key TEXT UNIQUE,setting_value TEXT)";
$q12="CREATE TABLE IF NOT EXISTS activity_log(id INTEGER PRIMARY KEY AUTOINCREMENT,admin_id INTEGER,action TEXT,details TEXT,ip_address TEXT,created_at DATETIME DEFAULT CURRENT_TIMESTAMP)";
foreach([$q1,$q2,$q3,$q4,$q5,$q6,$q7,$q8,$q9,$q10,$q11,$q12]as$q){$db->exec($q);}
if(!$db->query("SELECT COUNT(*) FROM admins")->fetchColumn()){ $db->prepare("INSERT INTO admins(username,password,email) VALUES(?,?,?)")->execute(["admin",password_hash("admin123",PASSWORD_DEFAULT),"admin@madrasa.edu"]);}
if(!$db->query("SELECT COUNT(*) FROM settings")->fetchColumn()){
$default_settings=[
["site_name","Madrasa Portal"],
["site_description","Gateway to Knowledge & Islamic Values"],
["contact_email","info@madrasa.edu"],
["contact_phone","+92-300-1234567"],
["contact_address","123 Islamic Center, Main Street, Lahore, Pakistan"],
["facebook_url","https://facebook.com/madrasaportal"],
["twitter_url","https://twitter.com/madrasaportal"],
["instagram_url","https://instagram.com/madrasaportal"],
["youtube_url","https://youtube.com/madrasaportal"],
["footer_text","© Madrasa Portal. All rights reserved."],
["allow_registration","0"],
["maintenance_mode","0"]
];
$stmt=$db->prepare("INSERT INTO settings(setting_key,setting_value) VALUES(?,?)");
foreach($default_settings as $s){$stmt->execute($s);}
}
}
init_db($db);
function auth_check() {return isset($_SESSION['admin']);}
function log_activity($action,$details=''){
global $db;
if(!auth_check())return;
$admin_id=$_SESSION['admin_id'];
$ip=$_SERVER['REMOTE_ADDR'];
$db->prepare("INSERT INTO activity_log(admin_id,action,details,ip_address) VALUES(?,?,?,?)")->execute([$admin_id,$action,$details,$ip]);
}
function get_setting($key,$default=''){
global $db;
$stmt=$db->prepare("SELECT setting_value FROM settings WHERE setting_key=?");
$stmt->execute([$key]);
$result=$stmt->fetch(PDO::FETCH_ASSOC);
return $result?$result['setting_value']:$default;
}
function output_json($data){ header('Content-Type: application/json');echo json_encode($data);exit;}
function handle_file_upload($input,$folder,$allowed_types=['jpg','jpeg','png','gif','pdf','doc','docx']){
if(isset($_FILES[$input])&&$_FILES[$input]['error']==UPLOAD_ERR_OK){
$ext=strtolower(pathinfo($_FILES[$input]['name'],PATHINFO_EXTENSION));
if(!in_array($ext,$allowed_types))return null;
$fname=$folder."/".uniqid().".".$ext;
move_uploaded_file($_FILES[$input]['tmp_name'],$fname);
return $fname;
}return null;}
function sanitize_output($text){return htmlspecialchars($text,ENT_QUOTES,'UTF-8');}
if(isset($_GET['api'])){
switch($_GET['api']){
case'login':
$d=json_decode(file_get_contents("php://input"),1);
$u=$d['user'];$p=$d['pass'];
$stmt=$db->prepare("SELECT * FROM admins WHERE username=?");
$stmt->execute([$u]);
$a=$stmt->fetch(PDO::FETCH_ASSOC);
if($a&&password_verify($p,$a['password'])){
$_SESSION['admin']=true;
$_SESSION['admin_id']=$a['id'];
$_SESSION['admin_name']=$a['username'];
$db->prepare("UPDATE admins SET last_login=CURRENT_TIMESTAMP WHERE id=?")->execute([$a['id']]);
log_activity('login','Admin logged in');
output_json(["ok"=>1,"admin"=>$a['username']]);
}output_json(["ok"=>0]);
case'check_auth':
if(auth_check()){
output_json(["ok"=>1,"admin"=>$_SESSION['admin_name']]);
}output_json(["ok"=>0]);
case'logout':
$admin=$_SESSION['admin_name']??'Unknown';
session_destroy();
output_json(["ok"=>1,"msg"=>"Logged out successfully"]);
case'change_password':
if(!auth_check())output_json(["ok"=>0,"error"=>"Not authorized"]);
$d=json_decode(file_get_contents("php://input"),1);
$np=$d['newpass'];$op=$d['oldpass'];
$stmt=$db->prepare("SELECT * FROM admins WHERE id=?");
$stmt->execute([$_SESSION['admin_id']]);
$ad=$stmt->fetch(PDO::FETCH_ASSOC);
if($ad&&password_verify($op,$ad['password'])){
$db->prepare("UPDATE admins SET password=? WHERE id=?")->execute([password_hash($np,PASSWORD_DEFAULT),$ad['id']]);
log_activity('password_change','Password changed');
output_json(["ok"=>1,"msg"=>"Password updated successfully"]);
}output_json(["ok"=>0,"error"=>"Current password is incorrect"]);
case'update_profile':
if(!auth_check())output_json(["ok"=>0,"error"=>"Not authorized"]);
$d=json_decode(file_get_contents("php://input"),1);
$stmt=$db->prepare("UPDATE admins SET username=?, email=? WHERE id=?");
$stmt->execute([$d['username'],$d['email'],$_SESSION['admin_id']]);
$_SESSION['admin_name']=$d['username'];
log_activity('profile_update','Admin profile updated');
output_json(["ok"=>1,"msg"=>"Profile updated successfully"]);
case'get_settings':
if(!auth_check())output_json(["ok"=>0,"error"=>"Not authorized"]);
$stmt=$db->query("SELECT * FROM settings");
$settings=$stmt->fetchAll(PDO::FETCH_ASSOC);
output_json($settings);
case'update_settings':
if(!auth_check())output_json(["ok"=>0,"error"=>"Not authorized"]);
$d=json_decode(file_get_contents("php://input"),1);
foreach($d as $key=>$value){
$stmt=$db->prepare("UPDATE settings SET setting_value=? WHERE setting_key=?");
$stmt->execute([$value,$key]);
}
log_activity('settings_update','Site settings updated');
output_json(["ok"=>1,"msg"=>"Settings updated successfully"]);
case'get_announcements':
$status=isset($_GET['status'])?$_GET['status']:'active';
$where=$status==='all'?'':'WHERE status="active"';
$arr=$db->query("SELECT * FROM announcements $where ORDER BY priority DESC, created_at DESC")->fetchAll(PDO::FETCH_ASSOC);
output_json($arr);
case'get_announcement':
$id=(int)$_GET['id'];
$stmt=$db->prepare("SELECT * FROM announcements WHERE id=?");
$stmt->execute([$id]);
$announcement=$stmt->fetch(PDO::FETCH_ASSOC);
if($announcement){output_json($announcement);}
else{output_json(["ok"=>0,"error"=>"Announcement not found"]);}
case'add_announcement':
if(!auth_check())output_json(["ok"=>0,"error"=>"Not authorized"]);
$d=json_decode(file_get_contents("php://input"),1);
$stmt=$db->prepare("INSERT INTO announcements(title,body,priority,status) VALUES(?,?,?,?)");
$stmt->execute([$d['title'],$d['body'],$d['priority']??0,$d['status']??'active']);
$id=$db->lastInsertId();
log_activity('announcement_add',"Added announcement ID: $id");
output_json(["ok"=>1,"msg"=>"Announcement added","id"=>$id]);
case'update_announcement':
if(!auth_check())output_json(["ok"=>0,"error"=>"Not authorized"]);
$d=json_decode(file_get_contents("php://input"),1);
$id=$d['id'];
$stmt=$db->prepare("UPDATE announcements SET title=?, body=?, priority=?, status=?, updated_at=CURRENT_TIMESTAMP WHERE id=?");
$stmt->execute([$d['title'],$d['body'],$d['priority']??0,$d['status']??'active',$id]);
log_activity('announcement_update',"Updated announcement ID: $id");
output_json(["ok"=>1,"msg"=>"Announcement updated"]);
case'del_announcement':
if(!auth_check())output_json(["ok"=>0,"error"=>"Not authorized"]);
$id=(int)$_GET['id'];
$db->prepare("DELETE FROM announcements WHERE id=?")->execute([$id]);
log_activity('announcement_delete',"Deleted announcement ID: $id");
output_json(["ok"=>1,"msg"=>"Announcement deleted"]);
case'get_teachers':
$status=isset($_GET['status'])?$_GET['status']:'active';
$where=$status==='all'?'':'WHERE status="active"';
$arr=$db->query("SELECT * FROM teachers $where ORDER BY name")->fetchAll(PDO::FETCH_ASSOC);
output_json($arr);
case'get_teacher':
$id=(int)$_GET['id'];
$stmt=$db->prepare("SELECT * FROM teachers WHERE id=?");
$stmt->execute([$id]);
$teacher=$stmt->fetch(PDO::FETCH_ASSOC);
if($teacher){output_json($teacher);}
else{output_json(["ok"=>0,"error"=>"Teacher not found"]);}
case'add_teacher':
if(!auth_check())output_json(["ok"=>0,"error"=>"Not authorized"]);
$name=$_POST['name'];
$profile=$_POST['profile'];
$position=$_POST['position']??'';
$qualification=$_POST['qualification']??'';
$experience=$_POST['experience']??'';
$email=$_POST['email']??'';
$phone=$_POST['phone']??'';
$subjects=$_POST['subjects']??'';
$status=$_POST['status']??'active';
$img=handle_file_upload('img','uploads');
$stmt=$db->prepare("INSERT INTO teachers(name,profile,img,position,qualification,experience,email,phone,subjects,status) VALUES(?,?,?,?,?,?,?,?,?,?)");
$stmt->execute([$name,$profile,$img,$position,$qualification,$experience,$email,$phone,$subjects,$status]);
$id=$db->lastInsertId();
log_activity('teacher_add',"Added teacher ID: $id");
output_json(["ok"=>1,"msg"=>"Teacher added","id"=>$id]);
case'update_teacher':
if(!auth_check())output_json(["ok"=>0,"error"=>"Not authorized"]);
$id=(int)$_POST['id'];
$name=$_POST['name'];
$profile=$_POST['profile'];
$position=$_POST['position']??'';
$qualification=$_POST['qualification']??'';
$experience=$_POST['experience']??'';
$email=$_POST['email']??'';
$phone=$_POST['phone']??'';
$subjects=$_POST['subjects']??'';
$status=$_POST['status']??'active';
$img=handle_file_upload('img','uploads');
$img_sql=$img?"img=?,":'';
$params=[$name,$profile,$position,$qualification,$experience,$email,$phone,$subjects,$status];
if($img)array_unshift($params,$img);
$params[]=$id;
$stmt=$db->prepare("UPDATE teachers SET name=?,profile=?,$img_sql position=?,qualification=?,experience=?,email=?,phone=?,subjects=?,status=? WHERE id=?");
$stmt->execute($params);
log_activity('teacher_update',"Updated teacher ID: $id");
output_json(["ok"=>1,"msg"=>"Teacher updated"]);
case'del_teacher':
if(!auth_check())output_json(["ok"=>0,"error"=>"Not authorized"]);
$id=(int)$_GET['id'];
$stmt=$db->prepare("SELECT img FROM teachers WHERE id=?");
$stmt->execute([$id]);
$img=$stmt->fetchColumn();
if($img&&file_exists($img))unlink($img);
$db->prepare("DELETE FROM teachers WHERE id=?")->execute([$id]);
log_activity('teacher_delete',"Deleted teacher ID: $id");
output_json(["ok"=>1,"msg"=>"Teacher deleted"]);
case'get_courses':
$status=isset($_GET['status'])?$_GET['status']:'active';
$where=$status==='all'?'':'WHERE c.status="active"';
try {
    $arr=$db->query("SELECT c.*, t.name as instructor_name FROM courses c LEFT JOIN teachers t ON c.instructor_id = t.id $where ORDER BY c.title")->fetchAll(PDO::FETCH_ASSOC);
    output_json($arr);
} catch(Exception $e) {
    output_json([]);
}
case'get_course':
$id=(int)$_GET['id'];
try {
    $stmt=$db->prepare("SELECT c.*, t.name as instructor_name FROM courses c LEFT JOIN teachers t ON c.instructor_id = t.id WHERE c.id=?");
    $stmt->execute([$id]);
    $course=$stmt->fetch(PDO::FETCH_ASSOC);
    if($course){output_json($course);}
    else{output_json(["ok"=>0,"error"=>"Course not found"]);}
} catch(Exception $e) {
    output_json(["ok"=>0,"error"=>"Database error"]);
}

case'add_course':
if(!auth_check())output_json(["ok"=>0,"error"=>"Not authorized"]);
$d=json_decode(file_get_contents("php://input"),1);
$stmt=$db->prepare("INSERT INTO courses(title,description,duration,fee,instructor_id,capacity,schedule,level,syllabus,status) VALUES(?,?,?,?,?,?,?,?,?,?)");
$stmt->execute([
$d['title'],$d['desc']??'',$d['duration']??'',$d['fee']??'',
$d['instructor_id']??null,$d['capacity']??null,$d['schedule']??'',
$d['level']??'',$d['syllabus']??'',$d['status']??'active'
]);
$id=$db->lastInsertId();
log_activity('course_add',"Added course ID: $id");
output_json(["ok"=>1,"msg"=>"Course added","id"=>$id]);
case'update_course':
if(!auth_check())output_json(["ok"=>0,"error"=>"Not authorized"]);
$d=json_decode(file_get_contents("php://input"),1);
$id=$d['id'];
$stmt=$db->prepare("UPDATE courses SET title=?,description=?,duration=?,fee=?,instructor_id=?,capacity=?,schedule=?,level=?,syllabus=?,status=? WHERE id=?");
$stmt->execute([
$d['title'],$d['desc'],$d['duration'],$d['fee'],$d['instructor_id'],
$d['capacity'],$d['schedule'],$d['level'],$d['syllabus'],$d['status'],$id
]);
log_activity('course_update',"Updated course ID: $id");
output_json(["ok"=>1,"msg"=>"Course updated"]);
case'del_course':
if(!auth_check())output_json(["ok"=>0,"error"=>"Not authorized"]);
$id=(int)$_GET['id'];
$db->prepare("DELETE FROM courses WHERE id=?")->execute([$id]);
log_activity('course_delete',"Deleted course ID: $id");
output_json(["ok"=>1,"msg"=>"Course deleted"]);
case'get_timetable':
$arr=$db->query("SELECT t.*, te.name as teacher_name FROM timetable t LEFT JOIN teachers te ON t.teacher_id = te.id ORDER BY CASE t.day WHEN 'Monday' THEN 1 WHEN 'Tuesday' THEN 2 WHEN 'Wednesday' THEN 3 WHEN 'Thursday' THEN 4 WHEN 'Friday' THEN 5 WHEN 'Saturday' THEN 6 WHEN 'Sunday' THEN 7 ELSE 8 END, t.time")->fetchAll(PDO::FETCH_ASSOC);
output_json($arr);
case'get_timetable_entry':
$id=(int)$_GET['id'];
$stmt=$db->prepare("SELECT * FROM timetable WHERE id=?");
$stmt->execute([$id]);
$entry=$stmt->fetch(PDO::FETCH_ASSOC);
if($entry){output_json($entry);}
else{output_json(["ok"=>0,"error"=>"Timetable entry not found"]);}
case'add_timetable':
if(!auth_check())output_json(["ok"=>0,"error"=>"Not authorized"]);
$d=json_decode(file_get_contents("php://input"),1);
$stmt=$db->prepare("INSERT INTO timetable(day,class,time,subject,teacher_id,room) VALUES(?,?,?,?,?,?)");
$stmt->execute([$d['day'],$d['class'],$d['time'],$d['subject']??'',$d['teacher_id']??null,$d['room']??'']);
$id=$db->lastInsertId();
log_activity('timetable_add',"Added timetable entry ID: $id");
output_json(["ok"=>1,"msg"=>"Timetable entry added","id"=>$id]);
case'update_timetable':
if(!auth_check())output_json(["ok"=>0,"error"=>"Not authorized"]);
$d=json_decode(file_get_contents("php://input"),1);
$id=$d['id'];
$stmt=$db->prepare("UPDATE timetable SET day=?,class=?,time=?,subject=?,teacher_id=?,room=? WHERE id=?");
$stmt->execute([$d['day'],$d['class'],$d['time'],$d['subject'],$d['teacher_id'],$d['room'],$id]);
log_activity('timetable_update',"Updated timetable entry ID: $id");
output_json(["ok"=>1,"msg"=>"Timetable entry updated"]);
case'del_timetable':
if(!auth_check())output_json(["ok"=>0,"error"=>"Not authorized"]);
$id=(int)$_GET['id'];
$db->prepare("DELETE FROM timetable WHERE id=?")->execute([$id]);
log_activity('timetable_delete',"Deleted timetable entry ID: $id");
output_json(["ok"=>1,"msg"=>"Timetable entry deleted"]);
case'get_gallery':
$category=isset($_GET['category'])?$_GET['category']:'';
$status=isset($_GET['status'])?$_GET['status']:'active';
$where=[];
if($status!=='all')$where[]="status='active'";
if($category)$where[]="category='$category'";
$where_clause=count($where)>0?'WHERE '.implode(' AND ',$where):'';
$arr=$db->query("SELECT * FROM gallery $where_clause ORDER BY event_date DESC, id DESC")->fetchAll(PDO::FETCH_ASSOC);
output_json($arr);
case'get_gallery_categories':
$arr=$db->query("SELECT DISTINCT category FROM gallery WHERE category IS NOT NULL AND category<>''")->fetchAll(PDO::FETCH_COLUMN);
output_json($arr);
case'get_gallery_item':
$id=(int)$_GET['id'];
$stmt=$db->prepare("SELECT * FROM gallery WHERE id=?");
$stmt->execute([$id]);
$item=$stmt->fetch(PDO::FETCH_ASSOC);
if($item){output_json($item);}
else{output_json(["ok"=>0,"error"=>"Gallery item not found"]);}
case'add_gallery':
if(!auth_check())output_json(["ok"=>0,"error"=>"Not authorized"]);
$caption=$_POST['caption'];
$category=$_POST['category']??'';
$event_date=$_POST['event_date']??date('Y-m-d');
$status=$_POST['status']??'active';
$img=handle_file_upload('img','uploads');
if(!$img)output_json(["ok"=>0,"error"=>"Image upload failed"]);
$stmt=$db->prepare("INSERT INTO gallery(img,caption,category,event_date,status) VALUES(?,?,?,?,?)");
$stmt->execute([$img,$caption,$category,$event_date,$status]);
$id=$db->lastInsertId();
log_activity('gallery_add',"Added gallery item ID: $id");
output_json(["ok"=>1,"msg"=>"Gallery item added","id"=>$id]);
case'update_gallery':
if(!auth_check())output_json(["ok"=>0,"error"=>"Not authorized"]);
$id=(int)$_POST['id'];
$caption=$_POST['caption'];
$category=$_POST['category']??'';
$event_date=$_POST['event_date']??date('Y-m-d');
$status=$_POST['status']??'active';
$img=handle_file_upload('img','uploads');
if($img){
$stmt=$db->prepare("SELECT img FROM gallery WHERE id=?");
$stmt->execute([$id]);
$old_img=$stmt->fetchColumn();
if($old_img&&file_exists($old_img))unlink($old_img);
$stmt=$db->prepare("UPDATE gallery SET img=?,caption=?,category=?,event_date=?,status=? WHERE id=?");
$stmt->execute([$img,$caption,$category,$event_date,$status,$id]);
}else{
$stmt=$db->prepare("UPDATE gallery SET caption=?,category=?,event_date=?,status=? WHERE id=?");
$stmt->execute([$caption,$category,$event_date,$status,$id]);
}
log_activity('gallery_update',"Updated gallery item ID: $id");
output_json(["ok"=>1,"msg"=>"Gallery item updated"]);
case'del_gallery':
if(!auth_check())output_json(["ok"=>0,"error"=>"Not authorized"]);
$id=(int)$_GET['id'];
$stmt=$db->prepare("SELECT img FROM gallery WHERE id=?");
$stmt->execute([$id]);
$img=$stmt->fetchColumn();
if($img&&file_exists($img))unlink($img);
$db->prepare("DELETE FROM gallery WHERE id=?")->execute([$id]);
log_activity('gallery_delete',"Deleted gallery item ID: $id");
output_json(["ok"=>1,"msg"=>"Gallery item deleted"]);
case'get_resources':
$category=isset($_GET['category'])?$_GET['category']:'';
$status=isset($_GET['status'])?$_GET['status']:'active';
$where=[];
if($status!=='all')$where[]="status='active'";
if($category)$where[]="category='$category'";
$where_clause=count($where)>0?'WHERE '.implode(' AND ',$where):'';
$arr=$db->query("SELECT * FROM resources $where_clause ORDER BY date_added DESC")->fetchAll(PDO::FETCH_ASSOC);
output_json($arr);
case'get_resource_categories':
$arr=$db->query("SELECT DISTINCT category FROM resources WHERE category IS NOT NULL AND category<>''")->fetchAll(PDO::FETCH_COLUMN);
output_json($arr);
case'get_resource':
$id=(int)$_GET['id'];
$stmt=$db->prepare("SELECT * FROM resources WHERE id=?");
$stmt->execute([$id]);
$resource=$stmt->fetch(PDO::FETCH_ASSOC);
if($resource){output_json($resource);}
else{output_json(["ok"=>0,"error"=>"Resource not found"]);}
case'add_resource':
if(!auth_check())output_json(["ok"=>0,"error"=>"Not authorized"]);
$title=$_POST['title'];
$description=$_POST['description']??'';
$category=$_POST['category']??'';
$status=$_POST['status']??'active';
$file=handle_file_upload('file','uploads',['pdf','doc','docx','ppt','pptx','xls','xlsx','txt','zip','rar']);
if(!$file)output_json(["ok"=>0,"error"=>"File upload failed"]);
$size=filesize($file);
$stmt=$db->prepare("INSERT INTO resources(title,file,description,category,size,status) VALUES(?,?,?,?,?,?)");
$stmt->execute([$title,$file,$description,$category,$size,$status]);
$id=$db->lastInsertId();
log_activity('resource_add',"Added resource ID: $id");
output_json(["ok"=>1,"msg"=>"Resource added","id"=>$id]);
case'update_resource':
if(!auth_check())output_json(["ok"=>0,"error"=>"Not authorized"]);
$id=(int)$_POST['id'];
$title=$_POST['title'];
$description=$_POST['description']??'';
$category=$_POST['category']??'';
$status=$_POST['status']??'active';
$file=handle_file_upload('file','uploads',['pdf','doc','docx','ppt','pptx','xls','xlsx','txt','zip','rar']);
if($file){
$stmt=$db->prepare("SELECT file FROM resources WHERE id=?");
$stmt->execute([$id]);
$old_file=$stmt->fetchColumn();
if($old_file&&file_exists($old_file))unlink($old_file);
$size=filesize($file);
$stmt=$db->prepare("UPDATE resources SET title=?,file=?,description=?,category=?,size=?,status=? WHERE id=?");
$stmt->execute([$title,$file,$description,$category,$size,$status,$id]);
}else{
$stmt=$db->prepare("UPDATE resources SET title=?,description=?,category=?,status=? WHERE id=?");
$stmt->execute([$title,$description,$category,$status,$id]);
}
log_activity('resource_update',"Updated resource ID: $id");
output_json(["ok"=>1,"msg"=>"Resource updated"]);
case'del_resource':
if(!auth_check())output_json(["ok"=>0,"error"=>"Not authorized"]);
$id=(int)$_GET['id'];
$stmt=$db->prepare("SELECT file FROM resources WHERE id=?");
$stmt->execute([$id]);
$file=$stmt->fetchColumn();
if($file&&file_exists($file))unlink($file);
$db->prepare("DELETE FROM resources WHERE id=?")->execute([$id]);
log_activity('resource_delete',"Deleted resource ID: $id");
output_json(["ok"=>1,"msg"=>"Resource deleted"]);
case'download':
$id=(int)$_GET['id'];
$r=$db->prepare("SELECT file,title FROM resources WHERE id=?");$r->execute([$id]);$f=$r->fetch(PDO::FETCH_ASSOC);
if($f&&file_exists($f['file'])){
$db->prepare("UPDATE resources SET downloads=downloads+1 WHERE id=?")->execute([$id]);
header('Content-Disposition: attachment; filename="'.$f['title'].'"');
header('Content-Type: application/octet-stream');
readfile($f['file']);exit;}
output_json(["ok"=>0,"error"=>"File not found"]);
case'get_faqs':
$category=isset($_GET['category'])?$_GET['category']:'';
$status=isset($_GET['status'])?$_GET['status']:'active';
$where=[];
if($status!=='all')$where[]="status='active'";
if($category)$where[]="category='$category'";
$where_clause=count($where)>0?'WHERE '.implode(' AND ',$where):'';
$arr=$db->query("SELECT * FROM faqs $where_clause ORDER BY display_order, id")->fetchAll(PDO::FETCH_ASSOC);
output_json($arr);
case'get_faq_categories':
$arr=$db->query("SELECT DISTINCT category FROM faqs WHERE category IS NOT NULL AND category<>''")->fetchAll(PDO::FETCH_COLUMN);
output_json($arr);
case'get_faq':
$id=(int)$_GET['id'];
$stmt=$db->prepare("SELECT * FROM faqs WHERE id=?");
$stmt->execute([$id]);
$faq=$stmt->fetch(PDO::FETCH_ASSOC);
if($faq){output_json($faq);}
else{output_json(["ok"=>0,"error"=>"FAQ not found"]);}
case'add_faq':
if(!auth_check())output_json(["ok"=>0,"error"=>"Not authorized"]);
$d=json_decode(file_get_contents("php://input"),1);
$stmt=$db->prepare("INSERT INTO faqs(question,answer,category,display_order,status) VALUES(?,?,?,?,?)");
$stmt->execute([$d['q'],$d['a'],$d['category']??'',$d['display_order']??0,$d['status']??'active']);
$id=$db->lastInsertId();
log_activity('faq_add',"Added FAQ ID: $id");
output_json(["ok"=>1,"msg"=>"FAQ added","id"=>$id]);
case'update_faq':
if(!auth_check())output_json(["ok"=>0,"error"=>"Not authorized"]);
$d=json_decode(file_get_contents("php://input"),1);
$id=$d['id'];
$stmt=$db->prepare("UPDATE faqs SET question=?,answer=?,category=?,display_order=?,status=? WHERE id=?");
$stmt->execute([$d['q'],$d['a'],$d['category']??'',$d['display_order']??0,$d['status']??'active',$id]);
log_activity('faq_update',"Updated FAQ ID: $id");
output_json(["ok"=>1,"msg"=>"FAQ updated"]);
case'del_faq':
if(!auth_check())output_json(["ok"=>0,"error"=>"Not authorized"]);
$id=(int)$_GET['id'];
$db->prepare("DELETE FROM faqs WHERE id=?")->execute([$id]);
log_activity('faq_delete',"Deleted FAQ ID: $id");
output_json(["ok"=>1,"msg"=>"FAQ deleted"]);
case'get_testimonials':
$approved=isset($_GET['approved'])?$_GET['approved']:null;
$where=$approved!==null?'WHERE approved='.(int)$approved:'';
$arr=$db->query("SELECT * FROM testimonials $where ORDER BY created_at DESC")->fetchAll(PDO::FETCH_ASSOC);
output_json($arr);
case'get_testimonial':
$id=(int)$_GET['id'];
$stmt=$db->prepare("SELECT * FROM testimonials WHERE id=?");
$stmt->execute([$id]);
$testimonial=$stmt->fetch(PDO::FETCH_ASSOC);
if($testimonial){output_json($testimonial);}
else{output_json(["ok"=>0,"error"=>"Testimonial not found"]);}
case'add_testimonial':
$d=json_decode(file_get_contents("php://input"),1);
$stmt=$db->prepare("INSERT INTO testimonials(name,msg,rating,approved) VALUES(?,?,?,?)");
$rating=isset($d['rating'])?(int)$d['rating']:5;
if($rating<1)$rating=1;if($rating>5)$rating=5;
$approved=auth_check()?1:0;
$stmt->execute([$d['name'],$d['msg'],$rating,$approved]);
$id=$db->lastInsertId();
if(auth_check())log_activity('testimonial_add',"Added testimonial ID: $id");
output_json(["ok"=>1,"msg"=>"Testimonial ".($approved?"added":"submitted for approval")]);
case'approve_testimonial':
if(!auth_check())output_json(["ok"=>0,"error"=>"Not authorized"]);
$id=(int)$_GET['id'];
$db->prepare("UPDATE testimonials SET approved=1 WHERE id=?")->execute([$id]);
log_activity('testimonial_approve',"Approved testimonial ID: $id");
output_json(["ok"=>1,"msg"=>"Testimonial approved"]);
case'del_testimonial':
if(!auth_check())output_json(["ok"=>0,"error"=>"Not authorized"]);
$id=(int)$_GET['id'];
$db->prepare("DELETE FROM testimonials WHERE id=?")->execute([$id]);
log_activity('testimonial_delete',"Deleted testimonial ID: $id");
output_json(["ok"=>1,"msg"=>"Testimonial deleted"]);
case'get_contacts':
if(!auth_check())output_json(["ok"=>0,"error"=>"Not authorized"]);
$status=isset($_GET['status'])?$_GET['status']:'all';
$where=$status==='all'?'':'WHERE status="'.$status.'"';
$arr=$db->query("SELECT * FROM contact $where ORDER BY created_at DESC")->fetchAll(PDO::FETCH_ASSOC);
output_json($arr);
case'get_contact':
if(!auth_check())output_json(["ok"=>0,"error"=>"Not authorized"]);
$id=(int)$_GET['id'];
$stmt=$db->prepare("SELECT * FROM contact WHERE id=?");
$stmt->execute([$id]);
$contact=$stmt->fetch(PDO::FETCH_ASSOC);
if($contact){output_json($contact);}
else{output_json(["ok"=>0,"error"=>"Contact not found"]);}
case'mark_contact_read':
if(!auth_check())output_json(["ok"=>0,"error"=>"Not authorized"]);
$id=(int)$_GET['id'];
$db->prepare("UPDATE contact SET status='read' WHERE id=?")->execute([$id]);
log_activity('contact_read',"Marked contact ID: $id as read");
output_json(["ok"=>1,"msg"=>"Marked as read"]);
case'add_contact':
$d=json_decode(file_get_contents("php://input"),1);
$db->prepare("INSERT INTO contact(name,email,msg) VALUES(?,?,?)")->execute([$d['name'],$d['email'],$d['msg']]);
output_json(["ok"=>1,"msg"=>"Message sent successfully"]);
case'reply_contact':
if(!auth_check())output_json(["ok"=>0,"error"=>"Not authorized"]);
$d=json_decode(file_get_contents("php://input"),1);
$db->prepare("UPDATE contact SET admin_reply=?, status='replied', replied_at=CURRENT_TIMESTAMP WHERE id=?")->execute([$d['reply'],$d['id']]);
log_activity('contact_reply',"Replied to contact ID: ".$d['id']);
output_json(["ok"=>1,"msg"=>"Reply sent"]);
case'get_activity_log':
if(!auth_check())output_json(["ok"=>0,"error"=>"Not authorized"]);
$limit=isset($_GET['limit'])?(int)$_GET['limit']:100;
$arr=$db->query("SELECT l.*, a.username FROM activity_log l LEFT JOIN admins a ON l.admin_id = a.id ORDER BY l.created_at DESC LIMIT $limit")->fetchAll(PDO::FETCH_ASSOC);
output_json($arr);
case'get_stats':
if(!auth_check())output_json(["ok"=>0,"error"=>"Not authorized"]);
$stats=[
'teachers'=>$db->query("SELECT COUNT(*) FROM teachers")->fetchColumn(),
'courses'=>$db->query("SELECT COUNT(*) FROM courses")->fetchColumn(),
'resources'=>$db->query("SELECT COUNT(*) FROM resources")->fetchColumn(),
'downloads'=>$db->query("SELECT SUM(downloads) FROM resources")->fetchColumn()?:0,
'testimonials'=>$db->query("SELECT COUNT(*) FROM testimonials WHERE approved=1")->fetchColumn(),
'pending_testimonials'=>$db->query("SELECT COUNT(*) FROM testimonials WHERE approved=0")->fetchColumn(),
'unread_messages'=>$db->query("SELECT COUNT(*) FROM contact WHERE status='unread'")->fetchColumn(),
];
output_json($stats);
}
exit;}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title><?php echo get_setting('site_name','Madrasa Portal'); ?></title>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<meta name="description" content="<?php echo get_setting('site_description','Madrasa Portal - Announcement, Timetable, Courses, Teachers, Gallery, Resources, and more.'); ?>"/>
<link rel="icon" href="data:,">
<style>
:root{
--main:#2A76D2;
--dark:#151B27;
--light:#F5F7FB;
--card:#fff;
--text:#222;
--accent:#55C594;
--danger:#E53935;
--warning:#FFA000;
--success:#43A047;
--radius:12px;
--shadow:0 2px 16px rgba(0,0,0,0.10);
--transition:all 0.25s ease;
--header-height:140px;
}
[data-theme="dark"]{
--main:#448AFF;
--dark:#181B22;
--light:#16191F;
--card:#252A35;
--text:#F4F6FB;
--accent:#65E0A7;
--danger:#FF5252;
--warning:#FFB300;
--success:#66BB6A;
}
*{box-sizing:border-box;margin:0;padding:0;}
html,body{height:100%;margin:0;font-family:"Segoe UI",Roboto,Arial,sans-serif;background:var(--light);color:var(--text);}
body{min-height:100vh;display:flex;flex-direction:column;line-height:1.6;}
header{background:var(--main);color:#fff;padding:22px 0 12px 0;text-align:center;box-shadow:var(--shadow);position:relative;}
nav{display:flex;justify-content:center;flex-wrap:wrap;gap:14px;padding:11px 0;}
nav button{background:none;border:none;color:#fff;font-weight:600;font-size:1rem;cursor:pointer;letter-spacing:.02em;padding:4px 12px;transition:.2s;}
nav button.active,nav button:hover{background:var(--accent);color:#1a1a1a;border-radius:4px;}
.switch-mode{position:absolute;top:20px;right:30px;background:var(--accent);color:var(--dark);border:none;padding:5px 13px;border-radius:6px;cursor:pointer;box-shadow:var(--shadow);}
#main{flex:1;max-width:1060px;margin:0 auto;padding:24px 8px 30px 8px;width:100%;}
.card{background:var(--card);border-radius:var(--radius);box-shadow:var(--shadow);padding:24px;margin-bottom:28px;transition:var(--transition);}
.card-title{font-size:1.4rem;font-weight:700;margin-bottom:10px;}
.card-sub{color:var(--main);font-weight:600;}
table{width:100%;border-collapse:collapse;margin:16px 0;border-radius:var(--radius);overflow:hidden;}
th,td{padding:10px 12px;text-align:left;vertical-align:middle;}
th{background:var(--main);color:#fff;}
td{background:var(--card);}
tr:nth-child(even) td{background:rgba(0,0,0,0.03);}
.button{background:var(--main);color:#fff;border:none;padding:7px 19px;border-radius:6px;cursor:pointer;font-size:.98rem;transition:var(--transition);display:inline-block;text-decoration:none;}
.button:hover{background:var(--accent);color:var(--dark);}
.button-sm{padding:4px 10px;font-size:.9rem;}
.button-danger{background:var(--danger);}
.button-danger:hover{background:#C62828;}
.button-success{background:var(--success);}
.button-success:hover{background:#2E7D32;}
.button-warning{background:var(--warning);}
.button-warning:hover{background:#FF8F00;}
.button-outline{background:transparent;border:1px solid var(--main);color:var(--main);}
.button-outline:hover{background:var(--main);color:#fff;}
.mt-10{margin-top:10px;}
.mt-20{margin-top:20px;}
.mb-10{margin-bottom:10px;}
.mb-20{margin-bottom:20px;}
.ml-10{margin-left:10px;}
.mr-10{margin-right:10px;}
.p-10{padding:10px;}
.p-20{padding:20px;}
.text-center{text-align:center;}
.text-right{text-align:right;}
.text-danger{color:var(--danger);}
.text-success{color:var(--success);}
.text-warning{color:var(--warning);}
.text-main{color:var(--main);}
.badge{display:inline-block;padding:3px 8px;border-radius:12px;font-size:0.8rem;font-weight:bold;}
.badge-success{background:var(--success);color:white;}
.badge-warning{background:var(--warning);color:white;}
.badge-danger{background:var(--danger);color:white;}
.badge-info{background:var(--main);color:white;}
@media(max-width:700px){
#main{padding:15px 7px;}
.card{padding:15px 10px;}
}
input,textarea,select{border:1px solid #b0b4ba;background:var(--light);color:var(--text);padding:9px 12px;border-radius:5px;width:100%;margin:7px 0 15px 0;font-size:1rem;transition:var(--transition);}
input:focus,textarea:focus,select:focus{outline:none;border-color:var(--main);box-shadow:0 0 0 2px rgba(42,118,210,0.2);}
input[type="file"]{padding:8px;margin:8px 0;}
input[type="checkbox"],input[type="radio"]{width:auto;margin-right:5px;}
label{font-weight:600;display:block;margin-top:10px;}
img.thumb{max-width:110px;max-height:70px;border-radius:8px;object-fit:cover;}
.flexrow{display:flex;flex-wrap:wrap;gap:17px;}
.flexcol-2{flex:1 1 320px;}
.flexcol-3{flex:1 1 250px;}
.flexcol-4{flex:1 1 200px;}
@keyframes fade{from{opacity:0;}to{opacity:1;}}
.fadein{animation:fade 0.4s ease-in-out;}
@keyframes slideIn{from{transform:translateY(20px);opacity:0;}to{transform:translateY(0);opacity:1;}}
.slidein{animation:slideIn 0.3s ease-out;}
.modal{display:none;position:fixed;z-index:1000;top:0;left:0;width:100vw;height:100vh;background:rgba(15,17,21,0.85);align-items:center;justify-content:center;backdrop-filter:blur(5px);}
.modal.active{display:flex;}
.modal-content{background:var(--card);padding:30px 25px 20px 25px;border-radius:10px;min-width:240px;max-width:97vw;max-height:90vh;overflow-y:auto;box-shadow:var(--shadow);position:relative;animation:slideIn 0.3s ease-out;}
.close{position:absolute;right:18px;top:15px;font-size:1.5rem;cursor:pointer;width:30px;height:30px;text-align:center;line-height:30px;border-radius:50%;transition:var(--transition);}
.close:hover{background:rgba(0,0,0,0.1);}
a{color:var(--main);text-decoration:none;transition:var(--transition);}
a:hover{color:var(--accent);}
footer{background:var(--dark);color:#fff;padding:20px 0;text-align:center;font-size:.97rem;margin-top:auto;}
[tabindex]:focus{outline:3px solid var(--main);}
::-webkit-scrollbar{width:8px;height:8px;}
::-webkit-scrollbar-track{background:var(--light);}
::-webkit-scrollbar-thumb{background:var(--main);border-radius:4px;}
::-webkit-scrollbar-thumb:hover{background:var(--accent);}
hr{border:none;border-top:1px solid rgba(125,125,125,0.2);margin:15px 0;}
.tabs{display:flex;border-bottom:1px solid rgba(125,125,125,0.2);margin-bottom:20px;}
.tab{padding:10px 15px;cursor:pointer;transition:var(--transition);}
.tab.active{border-bottom:2px solid var(--main);color:var(--main);font-weight:600;}
.tab:hover:not(.active){background:rgba(0,0,0,0.05);}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:20px;}
.card-hover:hover{transform:translateY(-5px);box-shadow:0 8px 25px rgba(0,0,0,0.15);}
.stats-card{text-align:center;padding:15px;transition:var(--transition);}
.stats-card:hover{transform:translateY(-5px);}
.stats-card .number{font-size:2.5rem;font-weight:bold;color:var(--main);margin:10px 0;}
.stats-card .label{font-size:1.1rem;color:var(--text);}
.search-box{margin-bottom:20px;position:relative;}
.search-box input{padding-left:40px;}
.search-box::before{content:'🔍';position:absolute;left:15px;top:50%;transform:translateY(-50%);opacity:0.5;}
.empty-state{text-align:center;padding:40px 20px;color:#888;}
.empty-state img,.empty-state svg{max-width:100px;margin-bottom:15px;opacity:0.5;}
.notification-dot{position:relative;}
.notification-dot::after{content:'';position:absolute;top:0;right:0;width:8px;height:8px;background:var(--danger);border-radius:50%;}
.loading{display:inline-block;width:20px;height:20px;border:3px solid rgba(255,255,255,.3);border-radius:50%;border-top-color:var(--main);animation:spin 1s ease-in-out infinite;}
@keyframes spin{to{transform:rotate(360deg);}}
.tooltip{position:relative;}
.tooltip:hover::after{content:attr(data-tooltip);position:absolute;bottom:100%;left:50%;transform:translateX(-50%);background:rgba(0,0,0,0.8);color:white;padding:5px 10px;border-radius:5px;font-size:0.8rem;white-space:nowrap;z-index:10;}
.social-links a{margin:0 10px;font-size:1.2rem;}
@media(prefers-color-scheme:dark){
:root:not([data-theme]){--main:#4397e9;--dark:#10141a;--light:#151A1E;--card:#1F2630;--text:#e7eafb;}
}
.dashboard-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:20px;}
.info-box{border-left:4px solid var(--main);padding-left:15px;}
.info-box.warning{border-color:var(--warning);}
.info-box.danger{border-color:var(--danger);}
.info-box.success{border-color:var(--success);}
.breadcrumb{display:flex;margin-bottom:15px;font-size:0.9rem;}
.breadcrumb span{margin:0 5px;opacity:0.7;}
.dropdown{position:relative;display:inline-block;}
.dropdown-content{display:none;position:absolute;background:var(--card);min-width:160px;box-shadow:var(--shadow);border-radius:var(--radius);z-index:100;right:0;}
.dropdown:hover .dropdown-content,.dropdown:focus .dropdown-content{display:block;}
.dropdown-item{padding:10px 15px;display:block;transition:var(--transition);}
.dropdown-item:hover{background:rgba(0,0,0,0.05);}
</style>
</head>
<body>
<button class="switch-mode" onclick="toggleMode()" aria-label="Switch color theme">🌙</button>
<header>
<h1><?php echo get_setting('site_name','Madrasa Portal'); ?></h1>
<span style="font-size:1.1rem;letter-spacing:.01em;"><?php echo get_setting('site_description','Gateway to Knowledge & Islamic Values'); ?></span>
<nav>
<button data-page="home" class="active" tabindex="0">Home</button>
<button data-page="announcements" tabindex="0">Announcements</button>
<button data-page="timetable" tabindex="0">Timetable</button>
<button data-page="teachers" tabindex="0">Teachers</button>
<button data-page="courses" tabindex="0">Courses</button>
<button data-page="gallery" tabindex="0">Gallery</button>
<button data-page="resources" tabindex="0">Resources</button>
<button data-page="testimonials" tabindex="0">Testimonials</button>
<button data-page="faq" tabindex="0">FAQ</button>
<button data-page="contact" tabindex="0">Contact</button>
<button data-page="admin" id="nav-admin" tabindex="0">Admin</button>
<button id="btn-logout" onclick="adminLogout()" style="display:none;" tabindex="0">Logout</button>
</nav>
</header>
<main id="main"><div id="loading" style="text-align:center;padding:50px;"><div class="loading"></div> Loading...</div></main>
<div id="modal" class="modal" tabindex="-1"><div class="modal-content" id="modal-content"></div></div>
<footer>
<div class="social-links">
<a href="<?php echo get_setting('facebook_url','#'); ?>" target="_blank" aria-label="Facebook">📱</a>
<a href="<?php echo get_setting('twitter_url','#'); ?>" target="_blank" aria-label="Twitter">🐦</a>
<a href="<?php echo get_setting('instagram_url','#'); ?>" target="_blank" aria-label="Instagram">📷</a>
<a href="<?php echo get_setting('youtube_url','#'); ?>" target="_blank" aria-label="Youtube">▶️</a>
</div>
<p><?php echo get_setting('footer_text','© '.date('Y').' Madrasa Portal. All rights reserved.'); ?></p>
</footer>
<script>
const mode=localStorage.getItem("theme");
if(mode){document.documentElement.setAttribute("data-theme",mode);}
function toggleMode(){
let t=document.documentElement.getAttribute("data-theme");
if(t=="dark"){document.documentElement.setAttribute("data-theme","light");localStorage.setItem("theme","light");}
else{document.documentElement.setAttribute("data-theme","dark");localStorage.setItem("theme","dark");}}
document.querySelector(".switch-mode").innerHTML=document.documentElement.getAttribute("data-theme")==="dark"?"☀️":"🌙";
document.querySelector(".switch-mode").onclick=function(){toggleMode();this.innerHTML=document.documentElement.getAttribute("data-theme")==="dark"?"☀️":"🌙";}
let adminMode=false;
let adminName='';
const PAGES=["home","announcements","timetable","teachers","courses","gallery","resources","testimonials","faq","contact","admin"];
function setNav(page){
document.querySelectorAll("nav button[data-page]").forEach(btn=>btn.classList.remove("active"));
let btn=document.querySelector('nav button[data-page="'+page+'"]');
if(btn)btn.classList.add("active");
}
async function fetchAPI(url,opts={}){
let r;
if(opts.files){
let fd=new FormData();
Object.entries(opts.files).forEach(([k,v])=>{if(v)fd.append(k,v);});
Object.entries(opts.body||{}).forEach(([k,v])=>fd.append(k,v));
r=await fetch(url,{method:'POST',body:fd});
}else{
r=await fetch(url,{
method:opts.method||'POST',
headers:{'Content-Type':'application/json'},
body:opts.body?JSON.stringify(opts.body):null
});
}
return await r.json();
}
function showModal(html,wide=false){
let m=document.getElementById("modal");
let mc=document.getElementById("modal-content");
mc.style.width=wide?'90%':'auto';
mc.style.maxWidth=wide?'1000px':'600px';
mc.innerHTML='<span class="close" onclick="closeModal()" tabindex="0" aria-label="Close">✕</span>'+html;
m.classList.add("active");
setTimeout(()=>mc.focus(),100);
}
function closeModal(){document.getElementById("modal").classList.remove("active");}
window.onclick=function(e){if(e.target==document.getElementById("modal"))closeModal();}
window.onkeydown=function(e){if(e.key=="Escape")closeModal();}
function toast(msg,type='info'){
let t=document.createElement("div");
t.innerHTML=msg;
let color='var(--main)';
if(type==='error')color='var(--danger)';
if(type==='success')color='var(--success)';
if(type==='warning')color='var(--warning)';
t.style.cssText=`background:${color};color:#fff;position:fixed;bottom:30px;left:50%;transform:translateX(-50%);padding:13px 25px;border-radius:7px;z-index:99;font-weight:600;box-shadow:var(--shadow);`;
document.body.appendChild(t);
setTimeout(()=>{t.style.opacity='0';t.style.transform='translateX(-50%) translateY(20px)';t.style.transition='all 0.5s ease';},2000);
setTimeout(()=>t.remove(),2500);
}
function lazyLoadImgs(){
document.querySelectorAll("img[data-src]").forEach(img=>{
if(isElementInViewport(img)){
img.setAttribute("src",img.getAttribute("data-src"));
img.removeAttribute("data-src");
}
});
}
function isElementInViewport(el){
const rect=el.getBoundingClientRect();
return(
rect.top>=0&&
rect.left>=0&&
rect.bottom<=(window.innerHeight||document.documentElement.clientHeight)&&
rect.right<=(window.innerWidth||document.documentElement.clientWidth)
);
}
function formatBytes(bytes,decimals=2){
if(bytes===0)return'0 Bytes';
const k=1024;
const dm=decimals<0?0:decimals;
const sizes=['Bytes','KB','MB','GB'];
const i=Math.floor(Math.log(bytes)/Math.log(k));
return parseFloat((bytes/Math.pow(k,i)).toFixed(dm))+' '+sizes[i];
}
function formatDate(dateString){
const options={year:'numeric',month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'};
return new Date(dateString).toLocaleString('en-US',options);
}
function htmlEscape(text){
return text
.replace(/&/g,"&amp;")
.replace(/</g,"&lt;")
.replace(/>/g,"&gt;")
.replace(/"/g,"&quot;")
.replace(/'/g,"&#039;");
}
let currentPage='';
async function loadPage(page){
if(page===currentPage)return;
currentPage=page;
setNav(page);
let main=document.getElementById("main");
main.innerHTML='<div class="fadein" id="loading" style="text-align:center;padding:50px;"><div class="loading"></div> Loading...</div>';
if(page=="home"){
main.innerHTML='<div class="card slidein"><div class="card-title">Welcome to Our Madrasa</div><div class="card-sub">A hub of Islamic learning & spiritual growth. Explore our programs, teachers, timetable, and more.</div><hr style="margin:15px 0;"><div class="flexrow"><div class="flexcol-2"><b>Why Choose Us?</b><ul><li>Qualified & passionate teachers</li><li>Structured courses for all ages</li><li>Inspirational environment</li><li>Modern facilities</li><li>Focus on character development</li></ul></div><div class="flexcol-2"><b>Quick Links</b><ul><li><a href="#" onclick="loadPage(\'courses\')">Our Courses</a></li><li><a href="#" onclick="loadPage(\'announcements\')">Latest Announcements</a></li><li><a href="#" onclick="loadPage(\'timetable\')">Class Timetable</a></li><li><a href="#" onclick="loadPage(\'contact\')">Contact Us</a></li>'+(adminMode?'':'<li><a href="#" onclick="loadPage(\'admin\')">Admin Login</a></li>')+'</ul></div></div></div>';
main.innerHTML+='<div class="flexrow"><div class="flexcol-2 card slidein"><div class="card-title">About Us</div><p>Our Madrasa is committed to providing quality Islamic education in a nurturing environment. We focus on teaching Quran, Hadith, Fiqh and Islamic values to students of all ages.</p><p>We believe in combining traditional Islamic teaching methods with modern educational approaches to ensure our students receive a comprehensive education.</p></div><div class="flexcol-2 card slidein"><div class="card-title">Contact Information</div><p><strong>Address:</strong> 123 Islamic Center, Main Street, Lahore, Pakistan</p><p><strong>Phone:</strong> +92-300-1234567</p><p><strong>Email:</strong> info@madrasa.edu</p><p><strong>Hours:</strong> Monday-Friday: 8:00 AM - 4:00 PM</p><p>Saturday: 9:00 AM - 2:00 PM</p></div></div>';
}
else if(page=="announcements"){
	let arr=await fetchAPI("?api=get_announcements");
let html='<div class="card slidein"><div class="card-title">Announcements</div>';
if(adminMode)html+='<button class="button" onclick="addAnnouncement()">Add New Announcement</button>';
html+='<div style="margin-top:13px;">';
if(arr.length===0){
html+='<div class="empty-state">No announcements available</div>';
} else {
arr.forEach(a=>{
html+='<div style="border-bottom:1px solid #e0e2e9;padding:12px 0;'+(a.priority>0?'background-color:rgba(255,235,156,0.2);padding-left:8px;border-left:3px solid var(--warning);':'')+'">';
html+='<div class="flexrow" style="align-items:center;justify-content:space-between;flex-wrap:nowrap;">';
html+='<strong>'+htmlEscape(a.title)+'</strong>';
html+='<span style="color:#9ca3b3;font-size:.95em;">'+(a.updated_at?'Updated: '+formatDate(a.updated_at):'Posted: '+formatDate(a.created_at))+'</span>';
html+='</div>';
html+='<div>'+htmlEscape(a.body)+'</div>';
if(a.status!=='active'){
html+='<div class="badge badge-warning">'+a.status+'</div>';
}
if(adminMode) {
html+='<div class="mt-10">';
html+='<button class="button button-sm" onclick="editAnnouncement('+a.id+')">Edit</button>';
html+=' <button class="button button-sm button-danger" onclick="delAnnouncement('+a.id+')">Delete</button>';
html+='</div>';
}
html+='</div>';
});
}
html+='</div></div>';
main.innerHTML=html;
}
else if(page=="timetable"){
let arr=await fetchAPI("?api=get_timetable");
let html='<div class="card slidein"><div class="card-title">Class Timetable</div>';
if(adminMode)html+='<div class="mb-10"><button class="button" onclick="addTimetable()">Add New Schedule</button></div>';
html+='<div class="table-responsive" style="overflow-x:auto;">';
html+='<table aria-label="Timetable"><tr><th>Day</th><th>Class</th><th>Time</th><th>Subject</th><th>Teacher</th>'+(adminMode?'<th>Room</th><th>Actions</th>':'')+'</tr>';
if(arr.length===0){
html+='<tr><td colspan="'+(adminMode?7:5)+'" class="text-center">No timetable entries available</td></tr>';
} else {
let currentDay = '';
arr.forEach((t, index) => {
const isNewDay = t.day !== currentDay;
currentDay = t.day;

    html+='<tr'+(isNewDay?' style="border-top:2px solid var(--main)"':'')+'>';
    html+='<td>'+(isNewDay?'<strong>'+t.day+'</strong>':'-')+'</td>';
    html+='<td>'+htmlEscape(t.class)+'</td>';
    html+='<td>'+htmlEscape(t.time)+'</td>';
    html+='<td>'+htmlEscape(t.subject||'-')+'</td>';
    html+='<td>'+htmlEscape(t.teacher_name||'-')+'</td>';
    if(adminMode) {
      html+='<td>'+htmlEscape(t.room||'-')+'</td>';
      html+='<td><button class="button button-sm" onclick="editTimetable('+t.id+')">Edit</button> ';
      html+='<button class="button button-sm button-danger" onclick="delTimetable('+t.id+')">Delete</button></td>';
    }
    html+='</tr>';
    });
}
html+='</table></div></div>';
main.innerHTML=html;
}
else if(page=="teachers"){
let arr=await fetchAPI("?api=get_teachers");
let html='<div class="card slidein"><div class="card-title">Our Teachers</div>';
if(adminMode)html+='<div class="mb-10"><button class="button" onclick="addTeacher()">Add New Teacher</button></div>';
html+='<div class="grid">';
if(arr.length===0){
html+='<div class="empty-state">No teachers available</div>';
} else {
arr.forEach(t=>{
html+='<div class="card card-hover" style="padding:15px;text-align:center;">';
if(t.img) {
html+='<img class="thumb" alt="'+htmlEscape(t.name)+'" src="'+t.img+'" style="width:120px;height:120px;border-radius:50%;object-fit:cover;margin:0 auto 10px auto;" loading="lazy">';
} else {
html+='<div style="width:120px;height:120px;border-radius:50%;background:var(--main);color:white;margin:0 auto 10px auto;display:flex;align-items:center;justify-content:center;font-size:3rem;">'+t.name.charAt(0)+'</div>';
}
html+='<h3>'+htmlEscape(t.name)+'</h3>';
html+='<div class="text-main">'+(t.position?htmlEscape(t.position):'Teacher')+'</div>';
if(t.qualification) html+='<div><small><strong>Qualification:</strong> '+htmlEscape(t.qualification)+'</small></div>';
html+='<div style="margin:10px 0;font-size:.95em;color:#667;">'+htmlEscape(t.profile)+'</div>';
if(t.email||t.phone||t.subjects) {
html+='<div style="font-size:0.9rem;margin-top:5px;">';
if(t.subjects) html+='<div><strong>Teaches:</strong> '+htmlEscape(t.subjects)+'</div>';
if(t.email) html+='<div><strong>Email:</strong> '+htmlEscape(t.email)+'</div>';
if(t.phone) html+='<div><strong>Phone:</strong> '+htmlEscape(t.phone)+'</div>';
html+='</div>';
}
if(adminMode) {
html+='<div class="mt-10">';
html+='<button class="button button-sm" onclick="editTeacher('+t.id+')">Edit</button> ';
html+='<button class="button button-sm button-danger" onclick="delTeacher('+t.id+')">Delete</button>';
html+='</div>';
}
html+='</div>';
});
}
html+='</div></div>';
main.innerHTML=html;
lazyLoadImgs();
}
else if(page=="courses"){
let arr=await fetchAPI("?api=get_courses");
let html='<div class="card slidein"><div class="card-title">Our Courses</div>';
if(adminMode)html+='<div class="mb-10"><button class="button" onclick="addCourse()">Add New Course</button></div>';
html+='<div class="flexrow">';
if(arr.length===0){
html+='<div class="empty-state">No courses available</div>';
} else {
arr.forEach(c=>{
html+='<div class="flexcol-2 card card-hover" style="margin-bottom:15px;">';
html+='<h3>'+htmlEscape(c.title)+'</h3>';
if(c.level) html+='<span class="badge badge-info">'+htmlEscape(c.level)+'</span> ';
html+='<div style="margin:10px 0;font-size:.98em;">'+htmlEscape(c.description)+'</div>';
html+='<div class="flexrow">';
if(c.duration||c.fee||c.instructor_name||c.capacity||c.schedule) {
html+='<div class="flexcol-2">';
if(c.duration) html+='<div><strong>Duration:</strong> '+htmlEscape(c.duration)+'</div>';
if(c.fee) html+='<div><strong>Fee:</strong> '+htmlEscape(c.fee)+'</div>';
if(c.instructor_name) html+='<div><strong>Instructor:</strong> '+htmlEscape(c.instructor_name)+'</div>';
html+='</div>';
html+='<div class="flexcol-2">';
if(c.capacity) html+='<div><strong>Capacity:</strong> '+htmlEscape(c.capacity)+'</div>';
if(c.schedule) html+='<div><strong>Schedule:</strong> '+htmlEscape(c.schedule)+'</div>';
html+='</div>';
}
html+='</div>';
if(c.syllabus) {
html+='<div class="mt-10"><strong>Syllabus:</strong> '+htmlEscape(c.syllabus)+'</div>';
}
if(adminMode) {
html+='<div class="mt-10">';
html+='<button class="button button-sm" onclick="editCourse('+c.id+')">Edit</button> ';
html+='<button class="button button-sm button-danger" onclick="delCourse('+c.id+')">Delete</button>';
html+='</div>';
}
html+='</div>';
});
}
html+='</div></div>';
main.innerHTML=html;
}
else if(page=="gallery"){
let categories = await fetchAPI("?api=get_gallery_categories");
let arr = await fetchAPI("?api=get_gallery");
let html='<div class="card slidein"><div class="card-title">Gallery</div>';
if(adminMode)html+='<div class="mb-10"><button class="button" onclick="addGallery()">Add New Image</button></div>';

if(categories.length > 0){
html+='<div class="tabs">';
html+='<div class="tab active" onclick="filterGallery(\'all\')">All</div>';
categories.forEach(cat => {
html+='<div class="tab" onclick="filterGallery(\''+cat+'\')">'+htmlEscape(cat)+'</div>';
});
html+='</div>';
}

html+='<div class="grid gallery-container">';
if(arr.length===0){
html+='<div class="empty-state">No images in the gallery</div>';
} else {
arr.forEach(g=>{
html+='<div class="card card-hover gallery-item" data-category="'+htmlEscape(g.category||'')+'" style="padding:10px;text-align:center;">';
html+='<img class="thumb" alt="'+htmlEscape(g.caption)+'" data-src="'+g.img+'" style="width:100%;height:180px;object-fit:cover;border-radius:var(--radius);" loading="lazy">';
html+='<div style="margin-top:10px;">'+htmlEscape(g.caption)+'</div>';
if(g.category) html+='<div class="badge badge-info">'+htmlEscape(g.category)+'</div>';
if(g.event_date) html+='<div style="font-size:0.8rem;color:#888;margin-top:5px;">'+formatDate(g.event_date).split(',')+'</div>';
if(adminMode) {
html+='<div class="mt-10">';
html+='<button class="button button-sm" onclick="editGallery('+g.id+')">Edit</button> ';
html+='<button class="button button-sm button-danger" onclick="delGallery('+g.id+')">Delete</button>';
html+='</div>';
}
html+='</div>';
});
}
html+='</div></div>';
main.innerHTML=html;
lazyLoadImgs();
window.filterGallery = function(category){
document.querySelectorAll('.tabs .tab').forEach(tab => {
tab.classList.remove('active');
});
event.target.classList.add('active');

document.querySelectorAll('.gallery-item').forEach(item => {
if(category === 'all' || item.dataset.category === category){
item.style.display = '';
} else {
item.style.display = 'none';
}
});
lazyLoadImgs();
};
}
else if(page=="resources"){
let categories = await fetchAPI("?api=get_resource_categories");
let arr = await fetchAPI("?api=get_resources");
let html='<div class="card slidein"><div class="card-title">Downloadable Resources</div>';
if(adminMode)html+='<div class="mb-10"><button class="button" onclick="addResource()">Add New Resource</button></div>';

if(categories.length > 0){
html+='<div class="tabs">';
html+='<div class="tab active" onclick="filterResources(\'all\')">All</div>';
categories.forEach(cat => {
html+='<div class="tab" onclick="filterResources(\''+cat+'\')">'+htmlEscape(cat)+'</div>';
});
html+='</div>';
}

html+='<div class="table-responsive" style="overflow-x:auto;">';
html+='<table aria-label="Resources"><tr><th>Title</th><th>Description</th>'+(categories.length>0?'<th>Category</th>':'')+'<th>Size</th><th>Downloads</th><th>Actions</th></tr>';
if(arr.length===0){
html+='<tr><td colspan="6" class="text-center">No resources available</td></tr>';
} else {
arr.forEach(r=>{
html+='<tr class="resource-item" data-category="'+htmlEscape(r.category||'')+'">';
html+='<td>'+htmlEscape(r.title)+'</td>';
html+='<td>'+(r.description?htmlEscape(r.description):'-')+'</td>';
if(categories.length>0) html+='<td>'+(r.category?htmlEscape(r.category):'-')+'</td>';
html+='<td>'+formatBytes(r.size||0)+'</td>';
html+='<td>'+r.downloads+'</td>';
html+='<td>';
html+='<a class="button button-sm button-success" href="?api=download&id='+r.id+'">Download</a>';
if(adminMode) {
html+=' <button class="button button-sm" onclick="editResource('+r.id+')">Edit</button>';
html+=' <button class="button button-sm button-danger" onclick="delResource('+r.id+')">Delete</button>';
}
html+='</td></tr>';
});
}
html+='</table></div></div>';
main.innerHTML=html;

window.filterResources = function(category){
document.querySelectorAll('.tabs .tab').forEach(tab => {
tab.classList.remove('active');
});
event.target.classList.add('active');

document.querySelectorAll('.resource-item').forEach(item => {
if(category === 'all' || item.dataset.category === category){
item.style.display = '';
} else {
item.style.display = 'none';
}
});
};
}
else if(page=="testimonials"){
let arr=await fetchAPI("?api=get_testimonials", {query: {approved: 1}});
let html='<div class="card slidein"><div class="card-title">Testimonials</div>';
html+='<div style="margin-bottom:15px"><button class="button" onclick="addTestimonial()">Add Your Testimonial</button></div>';
html+='<div class="grid">';
if(arr.length===0){
html+='<div class="empty-state">No testimonials available yet. Be the first to add one!</div>';
} else {
arr.forEach(t=>{
const stars = '⭐'.repeat(t.rating || 5);
html+='<div class="card card-hover" style="padding:20px;position:relative;">';
html+='<div style="position:absolute;top:10px;right:10px;font-size:1.2rem;">'+stars+'</div>';
html+='<div style="font-style:italic;margin-bottom:10px;">"'+htmlEscape(t.msg)+'"</div>';
html+='<div><strong>- '+htmlEscape(t.name)+'</strong></div>';
html+='<div style="font-size:0.8rem;color:#888;margin-top:5px;">'+formatDate(t.created_at).split(',')+'</div>';
if(adminMode) {
html+='<div class="mt-10">';
html+='<button class="button button-sm button-danger" onclick="delTestimonial('+t.id+')">Delete</button>';
html+='</div>';
}
html+='</div>';
});
}
html+='</div></div>';
if(adminMode) {
// Show pending testimonials section for admin
let pendingArr = await fetchAPI("?api=get_testimonials", {query: {approved: 0}});
if(pendingArr.length > 0) {
html+='<div class="card slidein"><div class="card-title">Pending Testimonials</div>';
html+='<div class="grid">';
pendingArr.forEach(t=>{
const stars = '⭐'.repeat(t.rating || 5);
html+='<div class="card" style="padding:20px;position:relative;border:2px solid var(--warning);">';
html+='<div style="position:absolute;top:10px;right:10px;font-size:1.2rem;">'+stars+'</div>';
html+='<div style="font-style:italic;margin-bottom:10px;">"'+htmlEscape(t.msg)+'"</div>';
html+='<div><strong>- '+htmlEscape(t.name)+'</strong></div>';
html+='<div style="font-size:0.8rem;color:#888;margin-top:5px;">Submitted: '+formatDate(t.created_at)+'</div>';
html+='<div class="mt-10">';
html+='<button class="button button-sm button-success" onclick="approveTestimonial('+t.id+')">Approve</button> ';
html+='<button class="button button-sm button-danger" onclick="delTestimonial('+t.id+')">Delete</button>';
html+='</div></div>';
});
html+='</div></div>';
}
}
main.innerHTML=html;
}
else if(page=="faq"){
let categories = await fetchAPI("?api=get_faq_categories");
let arr = await fetchAPI("?api=get_faqs");
let html='<div class="card slidein"><div class="card-title">Frequently Asked Questions</div>';
if(adminMode)html+='<div class="mb-10"><button class="button" onclick="addFaq()">Add New FAQ</button></div>';

if(categories.length > 0){
html+='<div class="tabs">';
html+='<div class="tab active" onclick="filterFaqs(\'all\')">All</div>';
categories.forEach(cat => {
html+='<div class="tab" onclick="filterFaqs(\''+cat+'\')">'+htmlEscape(cat)+'</div>';
});
html+='</div>';
}

html+='<div class="faq-container">';
if(arr.length===0){
html+='<div class="empty-state">No FAQs available</div>';
} else {
arr.forEach(f=>{
html+='<div class="faq-item" data-category="'+htmlEscape(f.category||'')+'" style="margin-bottom:20px;padding-bottom:15px;border-bottom:1px solid rgba(125,125,125,0.2);">';
html+='<div style="display:flex;justify-content:space-between;align-items:flex-start;">';
html+='<h3 class="mb-10">Q: '+htmlEscape(f.question)+'</h3>';
if(f.category) html+='<span class="badge badge-info">'+htmlEscape(f.category)+'</span>';
html+='</div>';
html+='<div style="color:#444;padding-left:15px;border-left:3px solid var(--main);">A: '+htmlEscape(f.answer)+'</div>';
if(adminMode) {
html+='<div class="mt-10">';
html+='<button class="button button-sm" onclick="editFaq('+f.id+')">Edit</button> ';
html+='<button class="button button-sm button-danger" onclick="delFaq('+f.id+')">Delete</button>';
html+='</div>';
}
html+='</div>';
});
}
html+='</div></div>';
main.innerHTML=html;

window.filterFaqs = function(category){
document.querySelectorAll('.tabs .tab').forEach(tab => {
tab.classList.remove('active');
});
event.target.classList.add('active');

document.querySelectorAll('.faq-item').forEach(item => {
if(category === 'all' || item.dataset.category === category){
item.style.display = '';
} else {
item.style.display = 'none';
}
});
};
}
else if(page=="contact"){
let html='<div class="card slidein"><div class="card-title">Contact Us</div>';
html+='<div class="flexrow">';
html+='<div class="flexcol-2">';
html+='<form id="contactform">';
html+='<label for="contact-name">Name</label>';
html+='<input id="contact-name" name="name" required tabindex="0">';
html+='<label for="contact-email">Email</label>';
html+='<input id="contact-email" type="email" name="email" required tabindex="0">';
html+='<label for="contact-msg">Message</label>';
html+='<textarea id="contact-msg" name="msg" rows="5" required tabindex="0"></textarea>';
html+='<button class="button" type="submit">Send Message</button>';
html+='</form>';
html+='<div id="contact-result" class="mt-10"></div>';
html+='</div>';
html+='<div class="flexcol-2">';
html+='<div class="info-box mb-20">';
html+='<h3>Visit Us</h3>';
html+='<p>123 Islamic Center, Main Street<br>Lahore, Pakistan</p>';
html+='</div>';
html+='<div class="info-box mb-20">';
html+='<h3>Call Us</h3>';
html+='<p>+92-300-1234567</p>';
html+='</div>';
html+='<div class="info-box mb-20">';
html+='<h3>Email Us</h3>';
html+='<p>info@madrasa.edu</p>';
html+='</div>';
html+='<div class="info-box">';
html+='<h3>Opening Hours</h3>';
html+='<p>Monday-Friday: 8:00 AM - 4:00 PM<br>Saturday: 9:00 AM - 2:00 PM<br>Sunday: Closed</p>';
html+='</div>';
html+='</div>';
html+='</div></div>';
main.innerHTML=html;
document.getElementById("contactform").onsubmit=async function(e){
e.preventDefault();
let formData = new FormData(this);
let body = Object.fromEntries(formData.entries());
let res=await fetchAPI("?api=add_contact",{body, method:"POST"});
if(res.ok){
toast("Message sent successfully!", "success");
this.reset();
document.getElementById("contact-result").innerHTML='<div class="info-box success">Thank you for reaching out! We will get back to you soon.</div>';
} else {
toast("Error sending message. Please try again.", "error");
}
};
}
else if(page=="admin"){
if(!adminMode){return showLogin();}

// Admin Dashboard
let stats = await fetchAPI("?api=get_stats");
let html='<div class="card slidein"><div class="card-title">Admin Dashboard</div>';
html+='<div class="breadcrumb"><a href="#" onclick="loadPage(\'admin\')">Dashboard</a></div>';

html+='<div class="dashboard-grid">';
html+='<div class="stats-card"><div class="number">'+stats.teachers+'</div><div class="label">Teachers</div></div>';
html+='<div class="stats-card"><div class="number">'+stats.courses+'</div><div class="label">Courses</div></div>';
html+='<div class="stats-card"><div class="number">'+stats.resources+'</div><div class="label">Resources</div></div>';
html+='<div class="stats-card"><div class="number">'+stats.downloads+'</div><div class="label">Downloads</div></div>';
html+='</div>';

if(stats.unread_messages > 0 || stats.pending_testimonials > 0) {
html+='<div class="card mt-10">';
html+='<h3>Notifications</h3>';
if(stats.unread_messages > 0) {
html+='<div class="info-box warning mt-10">';
html+='<div><strong>'+stats.unread_messages+'</strong> unread contact message'+(stats.unread_messages>1?'s':'')+'</div>';
html+='<a href="#" class="button button-sm mt-10" onclick="adminViewMessages()">View Messages</a>';
html+='</div>';
}
if(stats.pending_testimonials > 0) {
html+='<div class="info-box warning mt-10">';
html+='<div><strong>'+stats.pending_testimonials+'</strong> pending testimonial'+(stats.pending_testimonials>1?'s':'')+'</div>';
html+='<a href="#" class="button button-sm mt-10" onclick="loadPage(\'testimonials\')">Review Testimonials</a>';
html+='</div>';
}
html+='</div>';
}

html+='<div class="flexrow mt-10">';
html+='<div class="flexcol-2 card">';
html+='<h3>Quick Actions</h3>';
html+='<div class="grid" style="grid-template-columns:repeat(auto-fill,minmax(140px,1fr));margin-top:15px;">';
html+='<a class="button" style="text-align:center;margin:5px;" onclick="loadPage(\'announcements\')">Announcements</a>';
html+='<a class="button" style="text-align:center;margin:5px;" onclick="loadPage(\'teachers\')">Teachers</a>';
html+='<a class="button" style="text-align:center;margin:5px;" onclick="loadPage(\'courses\')">Courses</a>';
html+='<a class="button" style="text-align:center;margin:5px;" onclick="loadPage(\'timetable\')">Timetable</a>';
html+='<a class="button" style="text-align:center;margin:5px;" onclick="loadPage(\'gallery\')">Gallery</a>';
html+='<a class="button" style="text-align:center;margin:5px;" onclick="loadPage(\'resources\')">Resources</a>';
html+='<a class="button" style="text-align:center;margin:5px;" onclick="loadPage(\'faq\')">FAQ</a>';
html+='<a class="button" style="text-align:center;margin:5px;" onclick="adminViewMessages()">Messages</a>';
html+='</div>';
html+='</div>';
html+='<div class="flexcol-2 card">';
html+='<h3>Admin Tools</h3>';
html+='<div class="mt-10">';
html+='<button class="button mb-10 mr-10" onclick="editProfile()">Edit Profile</button>';
html+='<button class="button mb-10" onclick="changePwd()">Change Password</button>';
html+='</div>';
html+='<div class="mt-10">';
html+='<button class="button mb-10 mr-10" onclick="siteSettings()">Site Settings</button>';
html+='<button class="button mb-10" onclick="viewActivityLog()">Activity Log</button>';
html+='</div>';
html+='</div>';
html+='</div>';
html+='</div>';
main.innerHTML=html;
}
}
function showLogin(){
let html='<form id="adminlogin"><div class="card-title">Admin Login</div>';
html+='<label for="admin-user">Username</label><input id="admin-user" name="user" required tabindex="0">';
html+='<label for="admin-pass">Password</label><input id="admin-pass" name="pass" type="password" required tabindex="0">';
html+='<button class="button" type="submit">Login</button>';
html+='<p class="mt-10 text-center">Default credentials: admin / admin123</p>';
html+='</form>';
showModal(html);
document.getElementById("adminlogin").onsubmit=async function(e){
e.preventDefault();
let u=this.user.value,p=this.pass.value;
let res=await fetchAPI("?api=login",{body:{user:u,pass:p},method:"POST"});
if(res.ok){
adminMode=true;
adminName=res.admin;
closeModal();
document.getElementById("nav-admin").style.display='inline-block';
document.getElementById("btn-logout").style.display='inline-block';
toast("Welcome back, "+adminName+"!", "success");
loadPage("admin");
} else {
toast("Invalid username or password", "error");
}
};
}
function adminLogout(){
fetchAPI("?api=logout",{}).then(res=>{
adminMode=false;
adminName='';
document.getElementById("nav-admin").style.display='inline-block';
document.getElementById("btn-logout").style.display='none';
toast(res.msg||"Logged out successfully", "success");
loadPage("home");
});
}
function addAnnouncement(){
showModal(`<form id="addann">

<div class="card-title">Add New Announcement</div>
<label for="ann-title">Title</label>
<input id="ann-title" required name="title">
<label for="ann-body">Content</label>
<textarea id="ann-body" required name="body" rows="5"></textarea>
<label for="ann-priority">Priority (0-10)</label>
<input id="ann-priority" type="number" name="priority" min="0" max="10" value="0">
<label for="ann-status">Status</label>
<select id="ann-status" name="status">
  <option value="active">Active</option>
  <option value="draft">Draft</option>
</select>
<button class="button mt-10" type="submit">Add Announcement</button>
</form>`);
document.getElementById("addann").onsubmit=async function(e){
  e.preventDefault();
  let formData = new FormData(this);
  let body = Object.fromEntries(formData.entries());
  body.priority = parseInt(body.priority);
  let res=await fetchAPI("?api=add_announcement",{body});
  if(res.ok){
    closeModal();
    loadPage("announcements");
    toast("Announcement added successfully", "success");
  } else {
    toast("Error adding announcement", "error");
  }
};
}
function editAnnouncement(id){
fetchAPI("?api=get_announcement&id="+id).then(a => {
  showModal(`<form id="editann">
  <div class="card-title">Edit Announcement</div>
  <input type="hidden" name="id" value="${a.id}">
  <label for="ann-title">Title</label>
  <input id="ann-title" required name="title" value="${htmlEscape(a.title)}">
  <label for="ann-body">Content</label>
  <textarea id="ann-body" required name="body" rows="5">${htmlEscape(a.body)}</textarea>
  <label for="ann-priority">Priority (0-10)</label>
  <input id="ann-priority" type="number" name="priority" min="0" max="10" value="${a.priority||0}">
  <label for="ann-status">Status</label>
  <select id="ann-status" name="status">
    <option value="active" ${a.status==='active'?'selected':''}>Active</option>
    <option value="draft" ${a.status==='draft'?'selected':''}>Draft</option>
  </select>
  <button class="button mt-10" type="submit">Update Announcement</button>
  </form>`);
  document.getElementById("editann").onsubmit=async function(e){
    e.preventDefault();
    let formData = new FormData(this);
    let body = Object.fromEntries(formData.entries());
    body.priority = parseInt(body.priority);
    let res=await fetchAPI("?api=update_announcement",{body});
    if(res.ok){
      closeModal();
      loadPage("announcements");
      toast("Announcement updated successfully", "success");
    } else {
      toast("Error updating announcement", "error");
    }
  };
});
}
async function delAnnouncement(id){
if(confirm("Are you sure you want to delete this announcement?")){
  let res = await fetchAPI("?api=del_announcement&id="+id);
  if(res.ok){
    loadPage("announcements");
    toast("Announcement deleted successfully", "success");
  } else {
    toast("Error deleting announcement", "error");
  }
}
}
function addTeacher(){
showModal(`<form id="addteacher" enctype="multipart/form-data">
<div class="card-title">Add New Teacher</div>
<div class="flexrow">
  <div class="flexcol-2">
    <label for="teacher-name">Name</label>
    <input id="teacher-name" required name="name">
  </div>
  <div class="flexcol-2">
    <label for="teacher-position">Position</label>
    <input id="teacher-position" name="position">
  </div>
</div>
<label for="teacher-profile">Profile</label>
<textarea id="teacher-profile" required name="profile" rows="3"></textarea>

<div class="flexrow">
  <div class="flexcol-2">
    <label for="teacher-qualification">Qualification</label>
    <input id="teacher-qualification" name="qualification">
  </div>
  <div class="flexcol-2">
    <label for="teacher-experience">Experience</label>
    <input id="teacher-experience" name="experience">
  </div>
</div>

<div class="flexrow">
  <div class="flexcol-2">
    <label for="teacher-email">Email</label>
    <input id="teacher-email" name="email" type="email">
  </div>
  <div class="flexcol-2">
    <label for="teacher-phone">Phone</label>
    <input id="teacher-phone" name="phone">
  </div>
</div>
<label for="teacher-subjects">Subjects</label>
<input id="teacher-subjects" name="subjects">
<label for="teacher-img">Image</label>
<input id="teacher-img" type="file" name="img" accept="image/*">
<label for="teacher-status">Status</label>
<select id="teacher-status" name="status">
<option value="active">Active</option>
<option value="inactive">Inactive</option>
</select>
<button class="button mt-10" type="submit">Add Teacher</button>
</form>`, true); document.getElementById("addteacher").onsubmit=async function(e){   e.preventDefault();   let formData = new FormData(this);   let files = {img: this.img.files};   let body = Object.fromEntries(formData.entries());   delete body.img;   let res=await fetchAPI("?api=add_teacher",{files, body});   if(res.ok){     closeModal();     loadPage("teachers");     toast("Teacher added successfully", "success");   } else {     toast("Error adding teacher", "error");   } }; } function editTeacher(id){ fetchAPI("?api=get_teacher&id="+id).then(t => {   showModal(`<form id="editteacher" enctype="multipart/form-data">

  <div class="card-title">Edit Teacher</div>
  <input type="hidden" name="id" value="${t.id}">
  <div class="flexrow">
    <div class="flexcol-2">
      <label for="teacher-name">Name</label>
      <input id="teacher-name" required name="name" value="${htmlEscape(t.name)}">
    </div>
    <div class="flexcol-2">
      <label for="teacher-position">Position</label>
      <input id="teacher-position" name="position" value="${htmlEscape(t.position||'')}">
    </div>
    </div>
<label for="teacher-profile">Profile</label>
<textarea id="teacher-profile" required name="profile" rows="3">${htmlEscape(t.profile)}</textarea>

  <div class="flexrow">
    <div class="flexcol-2">
      <label for="teacher-qualification">Qualification</label>
      <input id="teacher-qualification" name="qualification" value="${htmlEscape(t.qualification||'')}">
    </div>
    <div class="flexcol-2">
      <label for="teacher-experience">Experience</label>
      <input id="teacher-experience" name="experience" value="${htmlEscape(t.experience||'')}">
    </div>
    </div>

  <div class="flexrow">
    <div class="flexcol-2">
      <label for="teacher-email">Email</label>
      <input id="teacher-email" name="email" type="email" value="${htmlEscape(t.email||'')}">
    </div>
    <div class="flexcol-2">
      <label for="teacher-phone">Phone</label>
      <input id="teacher-phone" name="phone" value="${htmlEscape(t.phone||'')}">
    </div>
    </div>
<label for="teacher-subjects">Subjects</label>
<input id="teacher-subjects" name="subjects" value="${htmlEscape(t.subjects||'')}">

  <div class="flexrow">
    <div class="flexcol-2">
      <label for="teacher-img">Current Image</label>
      ${t.img?'<img src="'+t.img+'" alt="Teacher" style="max-width:150px;max-height:150px;margin:10px 0;">':'<p>No image</p>'}
    </div>
    <div class="flexcol-2">
      <label for="teacher-img">Change Image</label>
      <input id="teacher-img" type="file" name="img" accept="image/*">
    </div>
    </div>
<label for="teacher-status">Status</label>
<select id="teacher-status" name="status">
<option value="active" ${t.status==='active'?'selected':''}>Active</option>
<option value="inactive" ${t.status==='inactive'?'selected':''}>Inactive</option>
</select>
<button class="button mt-10" type="submit">Update Teacher</button>
</form>`, true);   document.getElementById("editteacher").onsubmit=async function(e){     e.preventDefault();     let formData = new FormData(this);     let files = {img: this.img.files};     let body = Object.fromEntries(formData.entries());     delete body.img;     let res=await fetchAPI("?api=update_teacher",{files, body});     if(res.ok){       closeModal();       loadPage("teachers");       toast("Teacher updated successfully", "success");     } else {       toast("Error updating teacher", "error");     }   }; }); } async function delTeacher(id){ if(confirm("Are you sure you want to delete this teacher?")){   let res = await fetchAPI("?api=del_teacher&id="+id);   if(res.ok){     loadPage("teachers");     toast("Teacher deleted successfully", "success");   } else {     toast("Error deleting teacher", "error");   } } } async function addCourse(){ let teachers = await fetchAPI("?api=get_teachers"); let teacherOptions = teachers.map(t => `<option value="${t.id}">${htmlEscape(t.name)}</option>`).join('');

showModal(`<form id="addcourse">

<div class="card-title">Add New Course</div>
<div class="flexrow">
  <div class="flexcol-2">
    <label for="course-title">Title</label>
    <input id="course-title" required name="title">
  </div>
  <div class="flexcol-2">
    <label for="course-level">Level</label>
    <select id="course-level" name="level">
      <option value="Beginner">Beginner</option>
      <option value="Intermediate">Intermediate</option>
      <option value="Advanced">Advanced</option>
      <option value="All Levels">All Levels</option>
    </select>
  </div>
</div>
<label for="course-desc">Description</label>
<textarea id="course-desc" required name="desc" rows="3"></textarea>

<div class="flexrow">
  <div class="flexcol-2">
    <label for="course-duration">Duration</label>
    <input id="course-duration" name="duration" placeholder="e.g. 3 months">
  </div>
  <div class="flexcol-2">
    <label for="course-fee">Fee</label>
    <input id="course-fee" name="fee" placeholder="e.g. Rs. 2000/month">
  </div>
</div>

<div class="flexrow">
  <div class="flexcol-2">
    <label for="course-instructor">Instructor</label>
    <select id="course-instructor" name="instructor_id">
      <option value="">- Select Instructor -</option>
      ${teacherOptions}
    </select>
  </div>
  <div class="flexcol-2">
    <label for="course-capacity">Capacity</label>
    <input id="course-capacity" name="capacity" type="number" min="1">
  </div>
</div>
<label for="course-schedule">Schedule</label>
<input id="course-schedule" name="schedule" placeholder="e.g. Mon, Wed, Fri 10:00 AM - 12:00 PM">
<label for="course-syllabus">Syllabus</label>
<textarea id="course-syllabus" name="syllabus" rows="3"></textarea>
<label for="course-status">Status</label>
<select id="course-status" name="status">
<option value="active">Active</option>
<option value="upcoming">Upcoming</option>
<option value="closed">Closed</option>
</select>
<button class="button mt-10" type="submit">Add Course</button>
</form>`, true); document.getElementById("addcourse").onsubmit=async function(e){   e.preventDefault();   let formData = new FormData(this);   let body = Object.fromEntries(formData.entries());   if(body.instructor_id === "") body.instructor_id = null;   if(body.capacity === "") body.capacity = null;   let res=await fetchAPI("?api=add_course",{body});   if(res.ok){     closeModal();     loadPage("courses");     toast("Course added successfully", "success");   } else {     toast("Error adding course", "error");   } }; } async function editCourse(id){ let course = await fetchAPI("?api=get_course&id="+id); let teachers = await fetchAPI("?api=get_teachers"); let teacherOptions = teachers.map(t => `<option value="${t.id}" ${course.instructor_id==t.id?'selected':''}>${htmlEscape(t.name)}</option>`).join('');

showModal(`<form id="editcourse">

<div class="card-title">Edit Course</div>
<input type="hidden" name="id" value="${course.id}">
<div class="flexrow">
  <div class="flexcol-2">
    <label for="course-title">Title</label>
    <input id="course-title" required name="title" value="${htmlEscape(course.title)}">
  </div>
  <div class="flexcol-2">
    <label for="course-level">Level</label>
    <select id="course-level" name="level">
      <option value="Beginner" ${course.level==='Beginner'?'selected':''}>Beginner</option>
      <option value="Intermediate" ${course.level==='Intermediate'?'selected':''}>Intermediate</option>
      <option value="Advanced" ${course.level==='Advanced'?'selected':''}>Advanced</option>
      <option value="All Levels" ${course.level==='All Levels'?'selected':''}>All Levels</option>
    </select>
  </div>
</div>
<label for="course-desc">Description</label>
<textarea id="course-desc" required name="desc" rows="3">${htmlEscape(course.description||'')}</textarea>

<div class="flexrow">
  <div class="flexcol-2">
    <label for="course-duration">Duration</label>
    <input id="course-duration" name="duration" value="${htmlEscape(course.duration||'')}" placeholder="e.g. 3 months">
  </div>
  <div class="flexcol-2">
    <label for="course-fee">Fee</label>
    <input id="course-fee" name="fee" value="${htmlEscape(course.fee||'')}" placeholder="e.g. Rs. 2000/month">
  </div>
</div>

<div class="flexrow">
  <div class="flexcol-2">
    <label for="course-instructor">Instructor</label>
    <select id="course-instructor" name="instructor_id">
      <option value="">- Select Instructor -</option>
      ${teacherOptions}
    </select>
  </div>
  <div class="flexcol-2">
    <label for="course-capacity">Capacity</label>
    <input id="course-capacity" name="capacity" type="number" min="1" value="${course.capacity||''}">
  </div>
</div>
<label for="course-schedule">Schedule</label>
<input id="course-schedule" name="schedule" value="${htmlEscape(course.schedule||'')}" placeholder="e.g. Mon, Wed, Fri 10:00 AM - 12:00 PM">
<label for="course-syllabus">Syllabus</label>
<textarea id="course-syllabus" name="syllabus" rows="3">${htmlEscape(course.syllabus||'')}</textarea>
<label for="course-status">Status</label>
<select id="course-status" name="status">
<option value="active" ${course.status==='active'?'selected':''}>Active</option>
<option value="upcoming" ${course.status==='upcoming'?'selected':''}>Upcoming</option>
<option value="closed" ${course.status==='closed'?'selected':''}>Closed</option>
</select>
<button class="button mt-10" type="submit">Update Course</button>
</form>`, true); document.getElementById("editcourse").onsubmit=async function(e){   e.preventDefault();   let formData = new FormData(this);   let body = Object.fromEntries(formData.entries());   if(body.instructor_id === "") body.instructor_id = null;   if(body.capacity === "") body.capacity = null;   let res=await fetchAPI("?api=update_course",{body});   if(res.ok){     closeModal();     loadPage("courses");     toast("Course updated successfully", "success");   } else {     toast("Error updating course", "error");   } }; } async function delCourse(id){ if(confirm("Are you sure you want to delete this course?")){   let res = await fetchAPI("?api=del_course&id="+id);   if(res.ok){     loadPage("courses");     toast("Course deleted successfully", "success");   } else {     toast("Error deleting course", "error");   } } } async function addTimetable(){ let teachers = await fetchAPI("?api=get_teachers"); let teacherOptions = teachers.map(t => `<option value="${t.id}">${htmlEscape(t.name)}</option>`).join('');

showModal(`<form id="addtt">

<div class="card-title">Add New Timetable Entry</div>
<div class="flexrow">
  <div class="flexcol-2">
    <label for="tt-day">Day</label>
    <select id="tt-day" required name="day">
      <option value="Monday">Monday</option>
      <option value="Tuesday">Tuesday</option>
      <option value="Wednesday">Wednesday</option>
      <option value="Thursday">Thursday</option>
      <option value="Friday">Friday</option>
      <option value="Saturday">Saturday</option>
      <option value="Sunday">Sunday</option>
    </select>
  </div>
  <div class="flexcol-2">
    <label for="tt-time">Time</label>
    <input id="tt-time" required name="time" placeholder="e.g. 9:00 AM - 10:30 AM">
  </div>
</div>

<div class="flexrow">
  <div class="flexcol-2">
    <label for="tt-class">Class</label>
    <input id="tt-class" required name="class">
  </div>
  <div class="flexcol-2">
    <label for="tt-subject">Subject</label>
    <input id="tt-subject" name="subject">
  </div>
</div>

<div class="flexrow">
  <div class="flexcol-2">
    <label for="tt-teacher">Teacher</label>
    <select id="tt-teacher" name="teacher_id">
      <option value="">- Select Teacher -</option>
      ${teacherOptions}
    </select>
  </div>
  <div class="flexcol-2">
    <label for="tt-room">Room</label>
    <input id="tt-room" name="room">
  </div>
</div>
<button class="button mt-10" type="submit">Add Timetable Entry</button>
</form>`); document.getElementById("addtt").onsubmit=async function(e){   e.preventDefault();   let formData = new FormData(this);   let body = Object.fromEntries(formData.entries());   if(body.teacher_id === "") body.teacher_id = null;   let res=await fetchAPI("?api=add_timetable",{body});   if(res.ok){     closeModal();     loadPage("timetable");     toast("Timetable entry added successfully", "success");   } else {     toast("Error adding timetable entry", "error");   } }; } async function editTimetable(id){ let entry = await fetchAPI("?api=get_timetable_entry&id="+id); let teachers = await fetchAPI("?api=get_teachers"); let teacherOptions = teachers.map(t => `<option value="${t.id}" ${entry.teacher_id==t.id?'selected':''}>${htmlEscape(t.name)}</option>`).join('');

showModal(`<form id="edittt">

<div class="card-title">Edit Timetable Entry</div>
<input type="hidden" name="id" value="${entry.id}">
<div class="flexrow">
  <div class="flexcol-2">
    <label for="tt-day">Day</label>
    <select id="tt-day" required name="day">
      <option value="Monday" ${entry.day==='Monday'?'selected':''}>Monday</option>
      <option value="Tuesday" ${entry.day==='Tuesday'?'selected':''}>Tuesday</option>
      <option value="Wednesday" ${entry.day==='Wednesday'?'selected':''}>Wednesday</option>
      <option value="Thursday" ${entry.day==='Thursday'?'selected':''}>Thursday</option>
      <option value="Friday" ${entry.day==='Friday'?'selected':''}>Friday</option>
      <option value="Saturday" ${entry.day==='Saturday'?'selected':''}>Saturday</option>
      <option value="Sunday" ${entry.day==='Sunday'?'selected':''}>Sunday</option>
    </select>
  </div>
  <div class="flexcol-2">
    <label for="tt-time">Time</label>
    <input id="tt-time" required name="time" value="${htmlEscape(entry.time)}" placeholder="e.g. 9:00 AM - 10:30 AM">
  </div>
</div>

<div class="flexrow">
  <div class="flexcol-2">
    <label for="tt-class">Class</label>
    <input id="tt-class" required name="class" value="${htmlEscape(entry.class)}">
  </div>
  <div class="flexcol-2">
    <label for="tt-subject">Subject</label>
    <input id="tt-subject" name="subject" value="${htmlEscape(entry.subject||'')}">
  </div>
</div>

<div class="flexrow">
  <div class="flexcol-2">
    <label for="tt-teacher">Teacher</label>
    <select id="tt-teacher" name="teacher_id">
      <option value="">- Select Teacher -</option>
      ${teacherOptions}
    </select>
  </div>
  <div class="flexcol-2">
    <label for="tt-room">Room</label>
    <input id="tt-room" name="room" value="${htmlEscape(entry.room||'')}">
  </div>
</div>
<button class="button mt-10" type="submit">Update Timetable Entry</button>
</form>`); document.getElementById("edittt").onsubmit=async function(e){   e.preventDefault();   let formData = new FormData(this);   let body = Object.fromEntries(formData.entries());   if(body.teacher_id === "") body.teacher_id = null;   let res=await fetchAPI("?api=update_timetable",{body});   if(res.ok){     closeModal();     loadPage("timetable");     toast("Timetable entry updated successfully", "success");   } else {     toast("Error updating timetable entry", "error");   } }; } async function delTimetable(id){ if(confirm("Are you sure you want to delete this timetable entry?")){   let res = await fetchAPI("?api=del_timetable&id="+id);   if(res.ok){     loadPage("timetable");     toast("Timetable entry deleted successfully", "success");   } else {     toast("Error deleting timetable entry", "error");   } } } function addGallery(){ showModal(`<form id="addgal" enctype="multipart/form-data">

<div class="card-title">Add New Gallery Image</div>
<label for="gal-caption">Caption</label>
<input id="gal-caption" required name="caption">
<label for="gal-category">Category</label>
<input id="gal-category" name="category" placeholder="e.g. Events, Classes, Facilities">
<label for="gal-date">Event Date</label>
<input id="gal-date" type="date" name="event_date" value="${new Date().toISOString().split('T')}">
<label for="gal-img">Image</label>
<input id="gal-img" type="file" name="img" accept="image/*" required>
<label for="gal-status">Status</label>
<select id="gal-status" name="status">
  <option value="active">Active</option>
  <option value="inactive">Inactive</option>
</select>
<button class="button mt-10" type="submit">Add to Gallery</button>
</form>`);
document.getElementById("addgal").onsubmit=async function(e){
  e.preventDefault();
  let formData = new FormData(this);
  let files = {img: this.img.files};
  let body = Object.fromEntries(formData.entries());
  delete body.img;
  let res=await fetchAPI("?api=add_gallery",{files, body});
  if(res.ok){
    closeModal();
    loadPage("gallery");
    toast("Gallery image added successfully", "success");
  } else {
    toast("Error adding gallery image", "error");
  }
};
}
function editGallery(id){
fetchAPI("?api=get_gallery_item&id="+id).then(g => {
  let eventDate = g.event_date ? g.event_date.split(' ') : new Date().toISOString().split('T');
  
  showModal(`<form id="editgal" enctype="multipart/form-data">
  <div class="card-title">Edit Gallery Image</div>
  <input type="hidden" name="id" value="${g.id}">
  <label for="gal-caption">Caption</label>
  <input id="gal-caption" required name="caption" value="${htmlEscape(g.caption)}">
  <label for="gal-category">Category</label>
  <input id="gal-category" name="category" value="${htmlEscape(g.category||'')}" placeholder="e.g. Events, Classes, Facilities">
  <label for="gal-date">Event Date</label>
  <input id="gal-date" type="date" name="event_date" value="${eventDate}">
  <div class="flexrow">
    <div class="flexcol-2">
      <label for="gal-img-current">Current Image</label>
      <img src="${g.img}" alt="Gallery image" style="max-width:200px;max-height:150px;margin:10px 0;">
    </div>
    <div class="flexcol-2">
      <label for="gal-img">Change Image</label>
      <input id="gal-img" type="file" name="img" accept="image/*">
    </div>
    </div>
<label for="gal-status">Status</label>
<select id="gal-status" name="status">
<option value="active" ${g.status==='active'?'selected':''}>Active</option>
<option value="inactive" ${g.status==='inactive'?'selected':''}>Inactive</option>
</select>
<button class="button mt-10" type="submit">Update Gallery Image</button>
</form>`);   document.getElementById("editgal").onsubmit=async function(e){     e.preventDefault();     let formData = new FormData(this);     let files = {img: this.img.files};     let body = Object.fromEntries(formData.entries());     delete body.img;     let res=await fetchAPI("?api=update_gallery",{files, body});     if(res.ok){       closeModal();       loadPage("gallery");       toast("Gallery image updated successfully", "success");     } else {       toast("Error updating gallery image", "error");     }   }; }); } async function delGallery(id){ if(confirm("Are you sure you want to delete this gallery image?")){   let res = await fetchAPI("?api=del_gallery&id="+id);   if(res.ok){     loadPage("gallery");     toast("Gallery image deleted successfully", "success");   } else {     toast("Error deleting gallery image", "error");   } } } function addResource(){ showModal(`<form id="addr" enctype="multipart/form-data">
<div class="card-title">Add New Resource</div>
<label for="res-title">Title</label>
<input id="res-title" required name="title">
<label for="res-desc">Description</label>
<textarea id="res-desc" name="description" rows="3"></textarea>
<label for="res-category">Category</label>
<input id="res-category" name="category" placeholder="e.g. Books, Documents, Presentations">
<label for="res-file">File</label>
<input id="res-file" type="file" name="file" required>
<label for="res-status">Status</label>
<select id="res-status" name="status">
<option value="active">Active</option>
<option value="inactive">Inactive</option>
</select>
<button class="button mt-10" type="submit">Add Resource</button>
</form>`); document.getElementById("addr").onsubmit=async function(e){   e.preventDefault();   let formData = new FormData(this);   let files = {file: this.file.files};   let body = Object.fromEntries(formData.entries());   delete body.file;   let res=await fetchAPI("?api=add_resource",{files, body});   if(res.ok){     closeModal();     loadPage("resources");     toast("Resource added successfully", "success");   } else {     toast("Error adding resource", "error");   } }; } function editResource(id){ fetchAPI("?api=get_resource&id="+id).then(r => {   showModal(`<form id="editr" enctype="multipart/form-data">

  <div class="card-title">Edit Resource</div>
  <input type="hidden" name="id" value="${r.id}">
  <label for="res-title">Title</label>
  <input id="res-title" required name="title" value="${htmlEscape(r.title)}">
  <label for="res-desc">Description</label>
  <textarea id="res-desc" name="description" rows="3">${htmlEscape(r.description||'')}</textarea>
  <label for="res-category">Category</label>
  <input id="res-category" name="category" value="${htmlEscape(r.category||'')}" placeholder="e.g. Books, Documents, Presentations">
  <div class="flexrow">
    <div class="flexcol-2">
      <label>Current File</label>
      <div>${htmlEscape(r.file.split('/').pop())}</div>
      <div>Size: ${formatBytes(r.size)}</div>
      <div>Downloads: ${r.downloads}</div>
    </div>
    <div class="flexcol-2">
      <label for="res-file">Change File</label>
      <input id="res-file" type="file" name="file">
    </div>
  </div>
  <label for="res-status">Status</label>
  <select id="res-status" name="status">
    <option value="active" ${r.status==='active'?'selected':''}>Active</option>
    <option value="inactive" ${r.status==='inactive'?'selected':''}>Inactive</option>
  </select>
  <button class="button mt-10" type="submit">Update Resource</button>
  </form>`);
  document.getElementById("editr").onsubmit=async function(e){
    e.preventDefault();
    let formData = new FormData(this);
    let files = {file: this.file.files};
    let body = Object.fromEntries(formData.entries());
    delete body.file;
    let res=await fetchAPI("?api=update_resource",{files, body});
    if(res.ok){
      closeModal();
      loadPage("resources");
      toast("Resource updated successfully", "success");
    } else {
      toast("Error updating resource", "error");
    }
  };
});
}
async function delResource(id){
if(confirm("Are you sure you want to delete this resource?")){
  let res = await fetchAPI("?api=del_resource&id="+id);
  if(res.ok){
    loadPage("resources");
    toast("Resource deleted successfully", "success");
  } else {
    toast("Error deleting resource", "error");
  }
}
}
function addFaq(){
showModal(`<form id="addfq">
<div class="card-title">Add New FAQ</div>
<label for="faq-q">Question</label>
<input id="faq-q" required name="q">
<label for="faq-a">Answer</label>
<textarea id="faq-a" required name="a" rows="4"></textarea>
<label for="faq-category">Category</label>
<input id="faq-category" name="category" placeholder="e.g. General, Admissions, Classes">
<label for="faq-order">Display Order</label>
<input id="faq-order" type="number" name="display_order" min="0" value="0">
<label for="faq-status">Status</label>
<select id="faq-status" name="status">
  <option value="active">Active</option>
  <option value="inactive">Inactive</option>
</select>
<button class="button mt-10" type="submit">Add FAQ</button>
</form>`);
document.getElementById("addfq").onsubmit=async function(e){
  e.preventDefault();
  let formData = new FormData(this);
  let body = Object.fromEntries(formData.entries());
  body.display_order = parseInt(body.display_order);
  let res=await fetchAPI("?api=add_faq",{body});
  if(res.ok){
    closeModal();
    loadPage("faq");
    toast("FAQ added successfully", "success");
  } else {
    toast("Error adding FAQ", "error");
  }
};
}
function editFaq(id){
fetchAPI("?api=get_faq&id="+id).then(f => {
  showModal(`<form id="editfq">
  <div class="card-title">Edit FAQ</div>
  <input type="hidden" name="id" value="${f.id}">
  <label for="faq-q">Question</label>
  <input id="faq-q" required name="q" value="${htmlEscape(f.question)}">
  <label for="faq-a">Answer</label>
  <textarea id="faq-a" required name="a" rows="4">${htmlEscape(f.answer)}</textarea>
  <label for="faq-category">Category</label>
  <input id="faq-category" name="category" value="${htmlEscape(f.category||'')}" placeholder="e.g. General, Admissions, Classes">
  <label for="faq-order">Display Order</label>
  <input id="faq-order" type="number" name="display_order" min="0" value="${f.display_order||0}">
  <label for="faq-status">Status</label>
  <select id="faq-status" name="status">
    <option value="active" ${f.status==='active'?'selected':''}>Active</option>
    <option value="inactive" ${f.status==='inactive'?'selected':''}>Inactive</option>
  </select>
  <button class="button mt-10" type="submit">Update FAQ</button>
  </form>`);
  document.getElementById("editfq").onsubmit=async function(e){
    e.preventDefault();
    let formData = new FormData(this);
    let body = Object.fromEntries(formData.entries());
    body.display_order = parseInt(body.display_order);
    let res=await fetchAPI("?api=update_faq",{body});
    if(res.ok){
      closeModal();
      loadPage("faq");
      toast("FAQ updated successfully", "success");
    } else {
      toast("Error updating FAQ", "error");
    }
  };
});
}
async function delFaq(id){
if(confirm("Are you sure you want to delete this FAQ?")){
  let res = await fetchAPI("?api=del_faq&id="+id);
  if(res.ok){
    loadPage("faq");
    toast("FAQ deleted successfully", "success");
  } else {
    toast("Error deleting FAQ", "error");
  }
}
}
function addTestimonial(){
showModal(`<form id="addt">
<div class="card-title">Add New Testimonial</div>
<label for="test-name">Your Name</label>
<input id="test-name" name="name" required>
<label for="test-msg">Message</label>
<textarea id="test-msg" name="msg" required rows="4"></textarea>
<label for="test-rating">Rating (1-5)</label>
<select id="test-rating" name="rating">
  <option value="5">5 - Excellent ⭐⭐⭐⭐⭐</option>
  <option value="4">4 - Very Good ⭐⭐⭐⭐</option>
  <option value="3">3 - Good ⭐⭐⭐</option>
  <option value="2">2 - Fair ⭐⭐</option>
  <option value="1">1 - Poor ⭐</option>
</select>
<button class="button mt-10" type="submit">Submit Testimonial</button>
</form>`);
document.getElementById("addt").onsubmit=async function(e){
  e.preventDefault();
  let formData = new FormData(this);
  let body = Object.fromEntries(formData.entries());
  body.rating = parseInt(body.rating);
  let res=await fetchAPI("?api=add_testimonial",{body});
  if(res.ok){
    closeModal();
    loadPage("testimonials");
    if(adminMode){
      toast("Testimonial added successfully", "success");
    } else {
      toast("Thank you! Your testimonial has been submitted for approval.", "success");
    }
  } else {
    toast("Error submitting testimonial", "error");
  }
};
}
async function approveTestimonial(id){
let res = await fetchAPI("?api=approve_testimonial&id="+id);
if(res.ok){
  loadPage("testimonials");
  toast("Testimonial approved successfully", "success");
} else {
  toast("Error approving testimonial", "error");
}
}
async function delTestimonial(id){
if(confirm("Are you sure you want to delete this testimonial?")){
  let res = await fetchAPI("?api=del_testimonial&id="+id);
  if(res.ok){
    loadPage("testimonials");
    toast("Testimonial deleted successfully", "success");
  } else {
    toast("Error deleting testimonial", "error");
  }
} 
}
function adminViewMessages(){
fetchAPI("?api=get_contacts").then(msgs => {
  let html = `<div class="card-title">Contact Messages</div>`;
  
  // Filter tabs
  html += `<div class="tabs">
    <div class="tab active" onclick="filterMessages('all')">All</div>
    <div class="tab" onclick="filterMessages('unread')">Unread</div>
    <div class="tab" onclick="filterMessages('read')">Read</div>
    <div class="tab" onclick="filterMessages('replied')">Replied</div>
  </div>`;
  
  if(msgs.length === 0) {
    html += `<div class="empty-state">No contact messages found</div>`;
  } else {
    html += `<div style="max-height:70vh;overflow-y:auto;">`;
    msgs.forEach(m => {
      html += `<div class="message-item" data-status="${m.status}" style="border-bottom:1px solid rgba(125,125,125,0.2);padding:15px;margin-bottom:10px;${m.status==='unread'?'background-color:rgba(66,133,244,0.1);border-left:3px solid var(--main);':''}">`;
      html += `<div style="display:flex;justify-content:space-between;align-items:flex-start;">`;
      html += `<h3>${htmlEscape(m.name)}</h3>`;
      html += `<span class="badge badge-${m.status==='unread'?'info':m.status==='read'?'warning':'success'}">${m.status}</span>`;
      html += `</div>`;
      html += `<div><a href="mailto:${htmlEscape(m.email)}">${htmlEscape(m.email)}</a></div>`;
      html += `<div style="margin:10px 0;padding:10px;background:rgba(0,0,0,0.05);border-radius:5px;">${htmlEscape(m.msg)}</div>`;
      html += `<div style="font-size:0.8rem;color:#888;">Received: ${formatDate(m.created_at)}</div>`;
      
      if(m.admin_reply) {
        html += `<div style="margin-top:10px;padding:10px;background:rgba(67,160,71,0.1);border-left:3px solid var(--success);border-radius:5px;">`;
        html += `<div style="font-weight:bold;color:var(--success);">Your Reply:</div>`;
        html += `<div>${htmlEscape(m.admin_reply)}</div>`;
        html += `<div style="font-size:0.8rem;color:#888;">Replied: ${formatDate(m.replied_at)}</div>`;
        html += `</div>`;
      } else {
        html += `<div class="mt-10">`;
        if(m.status === 'unread') {
          html += `<button class="button button-sm button-outline" onclick="markMessageRead(${m.id})">Mark as Read</button> `;
        }
        html += `<button class="button button-sm" onclick="replyContact(${m.id})">Reply</button>`;
        html += `</div>`;
      }
      
      html += `</div>`;
    });
    html += `</div>`;
  }
  
  showModal(html, true);
  
  window.filterMessages = function(status) {
    document.querySelectorAll('.tabs .tab').forEach(tab => {
      tab.classList.remove('active');
    });
    event.target.classList.add('active');
    
    document.querySelectorAll('.message-item').forEach(item => {
      if(status === 'all' || item.dataset.status === status){
        item.style.display = '';
      } else {
        item.style.display = 'none';
      }
    });
  };
});
}
async function markMessageRead(id){
let res = await fetchAPI("?api=mark_contact_read&id="+id);
if(res.ok){
  adminViewMessages();
  toast("Message marked as read", "success");
} else {
  toast("Error updating message status", "error");
}
}
function replyContact(id){
fetchAPI("?api=get_contact&id="+id).then(c => {
  showModal(`<form id="replyc">
  <div class="card-title">Reply to ${htmlEscape(c.name)}</div>
  <input type="hidden" name="id" value="${c.id}">
  <div style="margin-bottom:15px;padding:10px;background:rgba(0,0,0,0.05);border-radius:5px;">
    <strong>Original Message:</strong><br>
    ${htmlEscape(c.msg)}
  </div>
<label for="reply-msg">Your Reply</label>
<textarea id="reply-msg" name="reply" required rows="5"></textarea>
<button class="button mt-10" type="submit">Send Reply</button>
</form>`);   document.getElementById("replyc").onsubmit=async function(e){     e.preventDefault();     let formData = new FormData(this);     let body = Object.fromEntries(formData.entries());     let res=await fetchAPI("?api=reply_contact",{body});     if(res.ok){       closeModal();       toast("Reply sent successfully", "success");       adminViewMessages();     } else {       toast("Error sending reply", "error");     }   }; }); } function changePwd(){ showModal(`<form id="chp">

<div class="card-title">Change Password</div>
<label for="old-pass">Current Password</label>
<input id="old-pass" name="oldpass" type="password" required>
<label for="new-pass">New Password</label>
<input id="new-pass" name="newpass" type="password" required>
<label for="conf-pass">Confirm New Password</label>
<input id="conf-pass" name="confpass" type="password" required>
<button class="button mt-10" type="submit">Update Password</button>
</form>`);
document.getElementById("chp").onsubmit=async function(e){
  e.preventDefault();
  let oldpass = this.oldpass.value;
  let newpass = this.newpass.value;
  let confpass = this.confpass.value;
  
  if(newpass !== confpass) {
    toast("New passwords don't match", "error");
    return;
  }
  
  if(newpass.length < 6) {
    toast("Password must be at least 6 characters", "error");
    return;
  }
  
  let res=await fetchAPI("?api=change_password",{body:{oldpass, newpass}});
  if(res.ok){
    closeModal();
    toast(res.msg, "success");
  } else {
    toast(res.error || "Failed to change password", "error");
  }
};
}
function editProfile(){
fetchAPI("?api=check_auth").then(data => {
  if(!data.ok) return;
  
  showModal(`<form id="edit-profile">
  <div class="card-title">Edit Admin Profile</div>
  <label for="admin-username">Username</label>
  <input id="admin-username" name="username" value="${htmlEscape(data.admin)}" required>
  <label for="admin-email">Email</label>
  <input id="admin-email" name="email" type="email">
  <button class="button mt-10" type="submit">Update Profile</button>
  </form>`);
  
  document.getElementById("edit-profile").onsubmit=async function(e){
    e.preventDefault();
    let formData = new FormData(this);
    let body = Object.fromEntries(formData.entries());
    let res=await fetchAPI("?api=update_profile",{body});
    if(res.ok){
      closeModal();
      adminName = body.username;
      toast(res.msg, "success");
    } else {
      toast(res.error || "Failed to update profile", "error");
    }
  };
});
}
async function viewActivityLog(){
let logs = await fetchAPI("?api=get_activity_log");
let html = `<div class="card-title">Activity Log</div>`;
html += `<div style="max-height:70vh;overflow-y:auto;">`;
html += `<table>
  <tr>
    <th>Admin</th>
    <th>Action</th>
    <th>Details</th>
    <th>Date & Time</th>
    <th>IP Address</th>
  </tr>`;

if(logs.length === 0) {
  html += `<tr><td colspan="5" class="text-center">No activity logs found</td></tr>`;
} else {
  logs.forEach(log => {
    html += `<tr>
      <td>${htmlEscape(log.username || 'Unknown')}</td>
      <td>${htmlEscape(log.action)}</td>
      <td>${htmlEscape(log.details || '-')}</td>
      <td>${formatDate(log.created_at)}</td>
      <td>${htmlEscape(log.ip_address)}</td>
    </tr>`;
  });
}

html += `</table></div>`;
showModal(html, true);
}
async function siteSettings(){
let settings = await fetchAPI("?api=get_settings");
let settingsObj = {};
settings.forEach(s => {
  settingsObj[s.setting_key] = s.setting_value;
});

let html = `<form id="site-settings">
<div class="card-title">Site Settings</div>
<div class="tabs">
  <div class="tab active" onclick="showSettingsTab('general')">General</div>
  <div class="tab" onclick="showSettingsTab('contact')">Contact</div>
  <div class="tab" onclick="showSettingsTab('social')">Social Media</div>
</div>
<div id="settings-general" class="settings-tab">
  <label for="site_name">Site Name</label>
  <input id="site_name" name="site_name" value="${htmlEscape(settingsObj.site_name || '')}">
  
  <label for="site_description">Site Description</label>
  <textarea id="site_description" name="site_description" rows="2">${htmlEscape(settingsObj.site_description || '')}</textarea>
  
  <label for="footer_text">Footer Text</label>
  <input id="footer_text" name="footer_text" value="${htmlEscape(settingsObj.footer_text || '')}">
  
  <label>
    <input type="checkbox" name="maintenance_mode" value="1" ${settingsObj.maintenance_mode === '1' ? 'checked' : ''}>
    Maintenance Mode
  </label>
</div>
<div id="settings-contact" class="settings-tab" style="display:none;">
  <label for="contact_email">Contact Email</label>
  <input id="contact_email" name="contact_email" value="${htmlEscape(settingsObj.contact_email || '')}">
  
  <label for="contact_phone">Contact Phone</label>
  <input id="contact_phone" name="contact_phone" value="${htmlEscape(settingsObj.contact_phone || '')}">
  
  <label for="contact_address">Contact Address</label>
  <textarea id="contact_address" name="contact_address" rows="3">${htmlEscape(settingsObj.contact_address || '')}</textarea>
</div>
<div id="settings-social" class="settings-tab" style="display:none;">
  <label for="facebook_url">Facebook URL</label>
  <input id="facebook_url" name="facebook_url" value="${htmlEscape(settingsObj.facebook_url || '')}">
  
  <label for="twitter_url">Twitter URL</label>
  <input id="twitter_url" name="twitter_url" value="${htmlEscape(settingsObj.twitter_url || '')}">
  
  <label for="instagram_url">Instagram URL</label>
  <input id="instagram_url" name="instagram_url" value="${htmlEscape(settingsObj.instagram_url || '')}">
  
  <label for="youtube_url">YouTube URL</label>
  <input id="youtube_url" name="youtube_url" value="${htmlEscape(settingsObj.youtube_url || '')}">
</div>
<button class="button mt-20" type="submit">Save Settings</button>
</form>`;

showModal(html, true);

window.showSettingsTab = function(tab) {
document.querySelectorAll('.tabs .tab').forEach(t => {
t.classList.remove('active');
});
event.target.classList.add('active');

document.querySelectorAll('.settings-tab').forEach(t => {
t.style.display = 'none';
});
document.getElementById('settings-' + tab).style.display = '';
};

document.getElementById("site-settings").onsubmit=async function(e){
e.preventDefault();
let formData = new FormData(this);
let body = Object.fromEntries(formData.entries());

// Handle checkbox values
body.maintenance_mode = body.maintenance_mode ? '1' : '0';

let res=await fetchAPI("?api=update_settings",{body});
if(res.ok){
closeModal();
toast("Settings updated successfully", "success");
// Reload current page to apply settings
loadPage(currentPage);
} else {
toast("Error updating settings", "error");
}
};
}
// Initialize the app
window.addEventListener("DOMContentLoaded",async function(){
// Check if already logged in
let auth = await fetchAPI("?api=check_auth");
if(auth.ok){
adminMode = true;
adminName = auth.admin;
document.getElementById("nav-admin").style.display='inline-block';
document.getElementById("btn-logout").style.display='inline-block';
} else {
document.getElementById("nav-admin").style.display='inline-block';
document.getElementById("btn-logout").style.display='none';
}

// Setup navigation
document.querySelectorAll("nav button[data-page]").forEach(btn=>{
btn.onclick=function(){loadPage(this.dataset.page);}
btn.onkeydown=function(e){if(e.key=="Enter"||e.key==" "){loadPage(this.dataset.page);e.preventDefault();}};
});

// Setup scroll event for lazy loading
window.addEventListener('scroll', function() {
if((window.innerHeight + window.scrollY) >= document.body.offsetHeight - 500) {
lazyLoadImgs();
}
});

// Load initial page
loadPage("home");
});
</script>
</body>
</html>
