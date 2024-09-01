```php
// デフォルトではVisitorという訪問者ログを取得するプラグインが実行されており、XSSに対して脆弱。
// リクエストヘッダ（User-Agent、X-FORWARDED-FOR）でログポイズニングが起きる
// 管理画面にログインしてVisitorページを開くと実行される
function VST_save_record() {
	global $wpdb;
	$table_name = $wpdb->prefix . 'VST_registros';

	VST_create_table_records();

	return $wpdb->insert(
				$table_name,
				array(
					'patch' => $_SERVER["REQUEST_URI"],
					'datetime' => current_time( 'mysql' ),
					'useragent' => $_SERVER['HTTP_USER_AGENT'],
					'ip' => $_SERVER['HTTP_X_FORWARDED_FOR']
				)
			);
}
```