# [Katana](https://github.com/Shogun147/Katana) 

使いやすい、Node.jsの侍たちの為のHMVCスケーラブルなWEBフレームワーク
=======

## コンテンツ

* [Features](#features)
* [Installation](#installation)
* [Quick start](#quick-start)
* [Routing](#routing)
* [Modules](#modules)
* [Controllers](#controllers)
  * [Hooks](#hooks)
* [Models](#models)
* [Views](#views)
* [Events](#events)
* [Sessions](#sessions)
* [Logging](#logging)
* [Examples](#examples)
* [Contributing](#contributing)
* [License](#license)

## Features

* 強力で柔軟性のあるクラシカルなルータ
* スケーラブルなHMVCアーキテクチャ
* 環境ベースのコンフィギュレーション
* アプリケーションのクイックジェネレータ
* Cookieとセッションのサポート
* テンプレート、パーシャルをサポート
* 完全にノンブロッキング
* …

## Installation

Katanaを最も早く使うには、npmでインストールすることです。

```bash
$ npm install -g katana
```

## Quick start

最も簡単に開始する方法は、アプリケーションを生成するKatana利用して実行することです。

```bash
$ katana create app
$ cd app
$ npm install
```

アプリのパスはオプションであり、現在のパスからの相対パスです。

これで、サーバを起動する準備が整いました。

```bash
$ node app
```

### 作成後の基本的なアプリケーションのレイアウトは次のようになります。
    .
    ├── app.js
    ├── application
    │   ├── config
    │   │   ├── development
    │   │   │   ├── application.js
    │   │   │   ├── routing.js
    │   │   │   └── stores.js
    │   │   └── production
    │   ├── controllers
    │   │   └── home.js
    │   ├── models
    │   └── views
    │       └── index.html
    ├── modules
    ├── public
    │   ├── images
    │   ├── scripts
    │   └── styles
    └── temp

## Routing

クラシカルなルーティングは、Katanaのフレームワークの中で最も強力なfutureの一つです。 これは、リクエストされたURIに対応するコントローラとアクションを決定するためにURIセグメントを使用しています。<br>
その為、他のNode.js フレームワークとは異なり、ルーティング ルールを作成することなく、コントローラーとアクションを追加するだけで、パスを変更でき、独自のルールを書くこともできます。<br>
ルールがない場合、URIパスとして扱われます： http://katana:8000/`controller`/`action`/`arg1`/../`argN`

もしそうであればURIのパスは次のとおりです。 `http://katana:8000/account/login`<br>
そして `controller=account` と `action=login` です。

URIセグメントがない場合、デフォルトパスは、`home`コントローラの`index`アクションが使用されます。

また、ユーザー·プロファイルを表示するような場合、ルーティングルールを設定することによって、パスを書き換えることができます。

```javascript
routes: {
  // 各リクエストメソッドは自身のルート（経路）があります。
  get: [
    ['user/:user_id', 'users/profile']
  ]

  // すべてのメソッドのためのルート（経路）を設定することもできます。
  all: [
    // リクエストされたメソッドをルート（経路）が一致しない場合は、このルートをしようとします
  ]
}
```

または、ルートプレフィックスとしてリクエストメソッドを設定できます：


```javascript
routes: [
  ['get user/:user_id', 'users/profile'], // これは get メソッドをルーティングします。
  ['* user/:user_id', 'users/profile'] // すべてのメソッド
  ['user/:user_id', 'users/profile'] // 設定されていない場合は、すべてのメソッドをチェックします
]
```


これは、`controller=users` と
`action=profile`を設定し、user_idは`Request.params.user_id`として利用できるようになります。

または、MVCモジュールにこのリクエストを渡すことができます：

```javascript
routes: {
  get: [
    ['user/:user_id', '#auth/users/profile']
  ]
}
```

このリクエストは、`auth`モジュール、`controller=users` と
`action=profile`をパスする`＃`シンボルを意味します。

また、次のようuser_idの書式を設定することができます：

```javascript
routes: {
  get: [
    ['user/:user_id([0-9]+)', '#auth/users/profile']
  ]
}
```

`!重要:` MVCモジュールは、独自のルーティングルールを持っているかもしれません。

その他の例：
  
```javascript
['news/:category/rss.:format(xml|json)?', 'news/rss'] will allow:
 news/any_category/rss
 news/any_category/rss.xml
 news/any_category/rss.json

 and News controller:

 methods: {
   rss: function(Response, Request) {
     // 今、Request.params.categoryとRequest.params.formatを使用することができます
     var format = Request.params.format || 'xml'; // default xml

     ...
   }
 }
```

## Modules

Katanaでは、モジュールはMVCの一部のアプリケーションとして、またはミドルウェアとして使用することができます。

MVCモジュールの場合は、メインMVCのと同じようにルーティングを使用することができます。<br>
また、runメソッドを呼び出すことにより、ウィジェットとしてそれらを実行することができます：

```javascript
Module('auth').run('users/list');
```

これは、`auth`モジュールから`users`コントローラの`list`アクションを実行します。

ミドルウェア モジュールは特定のアプリケーション イベントをリッスンし、彼らが必要とする対話をすることができます。

例えばauthモジュールは次のようになります。

```javascript
var User = App.Model('auth:user'); // authモジュールのuserモデルを取得

// listen new request event
App.on('request', function(Request, Response, callback) {
  Request.user = new User(Request.session);

  callback(); // アプリケーションが続行に必要な作業が終わったときのコールバック
});
```

その後コントローラからユーザーオブジェクト 'Request.user' としてアクセスできます。

### Sharing modules

[Katana](https://github.com/Shogun147/Katana)
はパブリックモジュールをダウンロードしてアプリケーションにインストールができる共有システム基本モジュールが付属しています。

Katanaバイナリがモジュールと対話するためにいくつかの新しいコマンドがあります。

* `katana modules` - 使用可能なすべてのモジュールを一覧表示。
* `katana modules-search <str>` - 'str' を含むモジュール名または記述を検索します。
* `katana modules-update` - モジュールのリストの関連情報を更新します。
* `katana modules-install <name> [url]` - アプリケーションモジュールのインストールまたは再インストールを行います。   * `name` or `name@version` -モジュール名
  * `url` or `username:repository` or `username:repository@version` - オプションurlまたは github username:repositoryの組み合わせ

   `name`　のみが提供された場合は、ダウンロードURLはモジュールレジストリファイルに含まれるモジュールのデータからビルドされます。名前は、バージョンタグが続く場合があります。<br>
  2番目の引数が url の場合はモジュールはその url からダウンロードされます。<br>
  2番目の引数が、 `username:repository@version` の組み合わせはurlです: `https://github.com/:username/:repository/tarball/:version` <br> 
  `version` がない場合は、要求されたものは、レジストリ内のモジュールに対して使用可能な最後のバージョンになるでしょう。有効なバージョンが次に検出されない場合の `master` ブランチが要求されます。<br>
  カスタムダウンロードURLモジュールの場合はgzipで圧縮されたtarballまだなければなりません。<br>
  インストール例:
    * `katana modules install auth`
    * `katana modules install auth@0.1.0`
    * `katana modules install Shogun147:Katana-auth`
    * `katana modules install Shogun147:Katana-auth@0.1.0`
    * `katana modules install https://github.com/Shogun147/Katana-auth/tarball/master`
    * `katana modules install http://my-site.com/downloads/module/v1.0.5`

* `katana modules uninstall <name>` - モジュールをアンインストールし削除する
* `katana modules enable <name>` - モジュールを有効にする
* `katana modules disable <name>` - モジュールを無効にする
* `katana modules` - list all available modules.
* `katana module search <str>` - search modules that contain `str` in name or description.
* `katana module update` - update modules list and their info.
* `katana module install <name> [url]` - install or reinstall app module.
  * `name` or `name@version` - module name
  * `url` or `username:repository` or `username:repository@version` - optional url or github username:repository combination.

このアクション [`install`, `uninstall`, `enable`, `disable`] のそれぞれに対してモジュールが呼びだされ、それらはhookを持っている可能性があります。hookは、モジュールのhooksディレクトリに格納されています。<br>
hookはこのアクションにユニークな何かをする必要があるときに便利です。 例えば、 `install` (modules/:name/hooks/install.js) hookは、publicディレクトリにデータベースまたはコピーモジュール資産の新しいテーブルを作成することができます...

モジュールのレジストリは `https://raw.github.com/Shogun147/Katana/master/modules.json`
からダウンロードされます。 リストに新しいモジュールを追加するには、単にこのファイルをforkしてpullリクエストを送信します。
これは、`katana modules` コマンドと検索記載される、あなたのモジュールになります。

## Controllers

コントローラは、あらゆるアプリケーションの最も重要な部分であり、それらは、着信リクエストを処理し、レスポンスを送信する。

シンプルなコントローラは次のようになります。

```javascript
// 独自のコントローラクラスを定義する
Class('Home_Controller', {
  isa: App.Controller, // Katanaコアコントローラを拡張

  methods: {
    index: function(Response, Request) {
      Response.send('Hello World!');
    }
  }
});

module.exports = new Home_Controller;
```

http://katana:8000/を開くことにより、この`index`アクションにアクセスすることができます。任意のURIパスがないので、
configのdefaultのコントローラの`home`とアクション`index`を使用します。また直接
http://katana:8000/`home`/ と `index` の defaultアクション まてゃ
http://katana:8000/`home`/`index` を開きアクセスすることができます。

### Hooks

Joose [Method
Modifiers(メソッド修飾子)]の力で(http://joose.github.com/Joose/doc/html/Joose/Manual/MethodModifiers.html)
(`before`, `after`, `override` and `around`) クラスのメソッドを呼び出す前、
またはメソッドの呼び出し後に発生する可能性があるアクションの結果を変更し、returnすることができます。

例えばindexメソッドはログインユーザーのみという制限をしましょう：

```javascript
Class('Home_Controller', {
  isa: App.Controller,

  methods: {
    index: function(Response, Request) {
      Response.send('Hello World!');
    }
  },

  around: {
    // ラップしたいメソッドと同名
    index: function(method, Response, Request) {
      var User = Request.user;

      // ユーザがログインしていない場合、次のログインページにリダイレクト
      if (!User.logged_in()) {
        return Response.redirect('/login');
      }

      // 他に、元のメソッドを呼び出す
      method(Response, Request);
    }
  }
});
```

`call`修飾子は、正規表現を使用してフック条件に一致するすべてのメソッドに適用することができます。

例えば、すべてのメソッドに対してアクセスを制限しましょう：

```javascript
Class('Home_Controller', {
  isa: App.Controller,

  methods: {
    index: function(Response, Request) {
      Response.send('Hello World!');
    }
  },

  call: {
    // メソッド名の代わりに正規表現を使う
    // これは、すべてのコントローラのメソッド呼び出しに適用されます
   '.*': function(method, Response, Request) {
      var User = Request.user;

      // ユーザがログインしていない場合、次のログインページにリダイレクト
      if (!User.logged_in()) {
        return Response.redirect('/login');
      }

      // 他に、元のメソッドを呼び出す
      method(Response, Request);
    }
  }
});
```


## Models

Katanaは何らかの方法でモデルを定義する場合や、特定のモジュールを使用する開発者を制限しませんでした。
それだけで、アプリケーションのモデル·ディレクトリまたはモジュールからすべてをオートロードし、ローカルレジストリに格納します。

アクセスするには次のようになります：<br>

    var News = App.Model('news'); // モデルオブジェクトを取得

モジュールからモデルを取得するには、コロン`:` でモジュール名とモデル·パスを分離する必要があります。
例えば、`auth`モジュールの呼び出しと`user`モデルの取得は、 `App.Model('auth:user')`

モデルファイルは次のようになります：

```javascript
var Mongoose = App.Store('mongoose'); // 格納されている設定ファイルを見て、mongooseの接続を取得
var Schema = require('mongoose').Schema;

var User = new Schema({
  username: String,
  password: String,
  email: String,
  signed_at: Date,
  roles: ['user', 'moderator', 'administrator']
});

module.exports = Mongoose.model('User', User);
```

## Views

viewをレンダリングするには、いくつかの方法を使用できます。

```javascript
var View = App.View;

Class('Home_Controller', {
  isa: App.Controller,

  methods: {
    index: function(Response, Request) {
      // 直接viewのコンテンツをレンダリングして送信
      Response.render('index', { title: 'Hello World' }); // this will render index.html file from views

      // コンテンツをレンダリング
      var content = View.render('index', { title: 'Hello World' });
      // その後、レスポンスを送信
      Response.send(content);

      // モジュールからviewをレンダリング
      Users.find({}, function(error, users) {
        if (error) { return Response.send('Error! Blablabla'); }

        // もう一度viewでモジュール名はパスとコロンで区切られる
        var list = View.render('auth:list', users);

        Response.render('index', { users: list });
      });
    }
  }
});
```

コントローラもthis.renderの呼び出しに渡されるグローバルデータを持つことができます：
  
```javascript
Class('Home_Controller', {
  isa: App.Controller,

  have: {
    // グローバルデータをコントローラに設定
    data: {
      title: 'This is title for all pages for this controller',
      total_requests: 0
    }
  },

  methods: {
    index: function(Response) {
      // アクションからグローバルデータをコントローラーに設定することもできます。
      this.set('copyright', 'blablabla');
      // または
      this.data.total_requests++;
    
      // this.renderメソッドを使用してビューをレンダリングすることにより、コントローラのデータは、このビューに渡します
      var content = this.render('index'); // <?-title?>, <?-total_requests?>
    
      // また、レンダリングにそれらを設定することによって、グローバルを書き換える場合があります
      var content = this.render('index', { title: 'This is rewritted title', foo: 'bar' });
    
      Response.send(content);
    }
  }
});
```

## Events

Katanaアプリケーションは、特定のイベントを別の手順でします。それらのいくつかはミドルウェアで利用可能で、それ以外は、ブートストラップ制御フローのためのものです。

例えば、`auth`モジュールが（Modulesを参照）のリクエストに対して、userモデルを割り当てるために`request`イベントをリッスンすることができます。

または、アプリケーションサーバで`chat`モジュール作成する場合、socket.ioサーバを必要になります。

```javascript
var socket_io = require('socket.io');
var io;

// Http.Serverがリスニング開始準備ができたらイベントを発行します
App.on('ready', function(callback) {
      io = socket_io.listen(App.server);
    
      io.sockets.on('connection', function (socket) {
        // …
      });
    
      callback();
});
```

## Sessions

Katanaはセッションをサポートするためのモジュールで構築しています。アプリのそれぞれの特定の訪問者をデータで関連付け、そのデータがリクエスト間で永続化するように設定する方法を示します。

### Data stores
今、Katanaは2つのセッションデータストアをサポートしています。(もっと来て）

* **Memory** (デフォルト):
  開発に便利です。セッションデータは、ワーカー·プロセス·レベルでのメモリーに保存され、これは、クラスタで動作しないことを意味します。アプリを再起動したときにも、すべてのセッションが消失されます。

* **Redis**:
  セッションはRedisのNOSQLデータベースに保存され、アプリを再起動しても持続されています。Redisのサーバーまたはclusterを必要とします。

### Using sessions

まずアプリケーション構成ファイルにセッションを有効にする必要があります。 デフォルトのセッションは、次のようになります。

```javascript
session: {
  // セッションのサポートを有効または無効にする
  enabled: true,

  // cookieのセッション識別子名
  key_name: 'session_id',

  // セッションIDの長さ
  key_length: 32,

  // 非アクティブなセッションを削除する前の有効期間
  lifetime: 1000 * 60 * 60 * 24 * 7,

  // セッションストアは,１つの config/stores.js から
  store: 'redis',
            
  // 新規セッションのデフォルトのデータ
  defaults: {
  
  }
}
```

いったんセッションを有効にすると、セッションオブジェクトは、各リクエストに割り当てられ、
データは、セッションストアから自動的にロードされます。このオブジェクトは
`Request.sessionの`としてアクセスすることができます。今のところは利用できるpublicメソッドは`set`、`get`と`remove`です。

ユーザーリクエストのカウンターの例

```javascript
index: function(Response, Request) {
  var Session = Request.session;

  // 現在のリクエスト数、デフォルトの0（ゼロ）を得る
  var counter = Session.get('requests', 0);

  counter++;

  // 新しい値を設定
  Session.set('requests', counter);

  // セッションデータは、自動的にレスポンスを送信する前にストアに保存されます
  // また、configのkey_nameからCookieにセッションIDを保存します。
  Response.send('You have visited this page '+ counter +' times');
}
```

## Logging

Katanaはログモジュール [winston](https://github.com/flatiron/winston)を使用しています。
`App.log`として使用されており、多くのトランスポートやオプションを追加できます。 公式のドキュメントを確認してください。

## Examples

* [ToDo](https://github.com/Shogun147/Katana-ToDo) - Simple todo application

## Contributing
興味があったり、どなたでもフレームワークの新しいアイデア、issueやpullリクエストを送って頂くことで、貢献頂けます。
お手伝い頂けるとありがたいです。

## License
The MIT License

Copyright © 2012 D.G. Shogun <Shogun147@gmail.com>
translate © 2012 dai_yamashita
