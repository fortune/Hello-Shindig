//
// Caja が使用されているとき、カウントダウン Feature で追加した
// メソッドの呼び出しが Caja に排除されないように、このコードで飼い慣らしておく（taming）。
//
var tamings___ = tamings___ || [];
tamings___.push(function(imports){
	___.grantRead(gadgets.countdown, 'init');
	___.grantRead(gadgets.countdown, 'timer');
	___.grantRead(gadgets.countdown, 'count');
});