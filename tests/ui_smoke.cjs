// Renders every dashboard screen against small synthetic state; no browser or network needed.
const fs = require('fs');
const vm = require('vm');
const app = {innerHTML:''};
const toast = {textContent:'',className:''};
const context = vm.createContext({
  document:{querySelector:selector=>selector==='#app'?app:toast,addEventListener:()=>{},cookie:''},
  window:{location:{origin:'https://pilot.example'}},
  localStorage:{getItem:()=>null,setItem:()=>{}},
  fetch:()=>new Promise(()=>{}),
  setTimeout:()=>0,clearTimeout:()=>{},
  console,
});
vm.runInContext(fs.readFileSync('agentic/web/app.js','utf8'),context);
vm.runInContext(`
  state.me={id:'u1',email:'owner@example.com',workspaces:[{id:'w1',name:'Agency',role:'owner'}]};
  state.workspace=state.me.workspaces[0];
  state.site={id:'s1',label:'Example',origin:'https://example.com',hostname:'example.com',automation_mode:'observe',crawls:[],open_findings:0};
  state.sites=[state.site];
  state.billing={site_count:1,usage:[]};
  const screens=['overview','sites','site','explorer','audit','plans','copilot','autofix','approvals','keywords','content','automation','analytics','agency','billing','activity','settings'];
  for(const screen of screens){
    state.page=screen;
    render();
    if(document.querySelector('#app').innerHTML.length<500){
      throw new Error('Screen did not render: '+screen);
    }
  }
`,context);
console.log('17 dashboard screens rendered');
