<?php
//mod start 20200329
//エラー調査
ini_set( 'display_errors', 1 );
ini_set( 'error_reporting', E_ALL );
//mod end 20200329

//セッション生成
session_start();

//クリックジャッキング対策
//クリック・ボタンなど偽装してクリックを誘い、意図しない動作をさせる
//X-FRAME-OPTIONSは外部から埋め込まれたほかのウェブページを表示を除外する
//フレーム内のページ表示を同一ドメイン内のみ許可
header('X-FRAME-OPTIONS: SAMEORIGIN');

//HTTPヘッダを明示的に設定
header("Content-type: text/html; charset=utf-8");

//セッションのトークンと、POST送信の際のトークンが一致しない場合
if ($_POST['token'] != $_SESSION['token']) {
    echo "ERR403：管理者にお問い合わせください";
    exit();
}

//入力値のスペースを削除するメソッド
function spaceTrim($str) {
    //正規表現で置換
    $str = preg_replace('/^[ 　]+/u', '', $str);
    $str = preg_replace('/[ 　]+$/u', '', $str);
    return $str;
}

//エラーを格納する変数
$errors = array();

//POST送信が空の場合
if (empty($_POST)) {
    //ログイン画面に戻る
    header("Location: index.php");
    exit();
} else {
    //変数がセットされていて、NULLでないこと
    $input_account = isset($_POST['account']) ? $_POST['account'] : NULL;
    $input_password = isset($_POST['password']) ? $_POST['password'] : NULL;

    $account = spaceTrim($input_account);
    $password = spaceTrim($input_password);

    //入力チェック
    if ($account == ''):
        $errors['account'] = "アカウントが入力されていません。";
    elseif(mb_strlen($account)>10):
        $errors['account_length'] = "アカウントは10文字以内で入力して下さい。";
    endif;
    if ($password == ''):
        $errors['password'] = "パスワードが入力されていません。";
    elseif(!preg_match('/^[0-9a-zA-Z]{8,15}$/', $_POST["password"])):
        $errors['password_length'] = "パスワードは半角英数字の8文字以上15文字以下で入力して下さい。";
    else:
        //文字列の反復
        $password_hide = str_repeat('*', strlen($password));
    endif;
}

//エラーがない場合
if (count($errors) === 0) {
    try {
        //外部ファイルの読み込み
        require_once("../db/db.php");

        //DB接続情報
        $dbh = db_connect();

        $statement = $dbh->prepare("SELECT account_name, password FROM GE_D_CUSTOMER WHERE account_name = (:account) AND del_flg = 0");
        $statement->bindValue(':account', $account, PDO::PARAM_STR);
        $statement->execute();

        //クエリ実行結果の取得
        if ($row = $statement->fetch()) {
            //ハッシュ化されているDBの値を取得
            $password_hash = $row[password];

            //入力パスワードとハッシュ化パスワードが一致するか
            if (password_verify($password, $password_hash)) {
                //外部ファイルの読み込み
                require_once('../private/ge_conf.php');

                //現在のセッションIDを新しいものに置き換える
                session_regenerate_id(true);

                //入力されたアカウント名をセッションに格納
                $_SESSION['account'] = $account;

                // 権限による画面遷移先の指定
                if ($_SESSION['account'] == ROOT_USER) {
                    //管理者ユーザー
                    header("Location: ../main/adminMainMenue.php");
                    exit();
                } else {
                    //一般ユーザー
                    header("Location: ../main/mainMenue.php");
                    exit();
                }
            } else {
                $errors['password'] = "アカウント及びパスワードが一致しません。";
            }
        } else {
            $errors['account'] = "アカウント及びパスワードが一致しません。";
        }
        //接続オブジェクト破棄
        $dbh = null;
    } catch(PDOException $e) {
        print('Error:'.$e->getMessage());
        die();
    }
}
?>

<!DOCTYPE html>
<html>
    <head>
        <title>ログイン確認画面</title>
        <meta charset="utf-8">
    </head>

    <body>
        <div>
            <h1>
                <a>ログイン</a>
             </h1>
        </div>
        <h1>ログインエラー</h1>
        <!-- エラーがあった場合、エラーの内容を出力 -->
        <?php if(count($errors) > 0): ?>
        <?php
            foreach($errors as $value) {
                echo "<p>".$value."<p>";
            }
        ?>
        <input type="button" value="戻る" onClick="history.back()">
        <?php endif; ?>
    </body>
</html>
