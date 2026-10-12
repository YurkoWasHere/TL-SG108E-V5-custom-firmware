// Test the exact browser script embedded in the candidate image, without dependencies.
const fs=require('node:fs'), vm=require('node:vm'), assert=require('node:assert/strict');
const html=fs.readFileSync(require('node:path').join(__dirname,'../patch/mac_table.html'),'utf8');
const script=html.match(/<script>([\s\S]*?)<\/script>/)[1];
function setup(fetch){
  const elements={};
  function element(){return {textContent:'',disabled:false,children:[],append(x){this.children.push(x)},replaceChildren(){this.children=[]}};}
  const context=vm.createContext({document:{getElementById:id=>elements[id]??=element(),createElement:element},fetch,AbortController,setTimeout,clearTimeout});
  vm.runInContext(script,context);
  return {context,elements};
}
const {context}=setup(()=>{});
function decode(s){return vm.runInContext(`decodeLine(${JSON.stringify(s)})`,context);}
assert.equal(decode('0000 1000 4455 2233 0011 2001 0b00 0000').entry[0],'00:11:22:33:44:55');
assert.equal(decode('0000 1000 4455 2233 0011 a001 0b00 0000').entry[1],11);
assert.equal(decode('0000 1000 4455 2233 0011 2001 0000 0020').entry[4],'Static');
assert.equal(decode('0000 1000 4455 2233 0011 2fff 0838 0000').entry[2],4095);
assert.equal(decode('0000 1000 4455 2233 0011 0fff 0838 0000').entry[2],7);
for(const line of [
  '0000 0000 4455 2233 0011 2001 0b00 0000', // lookup miss
  '0000 1000 4455 2233 0111 2001 0b00 0000', // multicast
  '0000 1000 4455 2233 0011 3001 0b00 0000', // IP lookup
  '0000 1000 4455 2233 0011 2001 0000 0000', // aged out
  '0000 1000 0000 0000 0000 2001 0b00 0000', // empty MAC
])assert.equal(decode(line).entry,null);
assert.throws(()=>decode('not a record'));
function block(n){return 'MACT1\n'+Array.from({length:64},(_,i)=>(n*64+i).toString(16).padStart(4,'0')+' 1000 4455 2233 0011 2001 0b00 0000\n').join('')+'END\n';}
(async()=>{
  let requests=0;
  let s=setup(async(url,opts)=>{assert.equal(url,`/MacTable${requests.toString(16).padStart(2,'0')}.dat`);assert.equal(opts.cache,'no-store');return {ok:true,text:async()=>block(requests++)};});
  await s.elements.read.onclick();assert.equal(requests,65);assert.equal(s.elements.rows.children.length,4160);assert.match(s.elements.status.textContent,/Complete: 4160 entries; 65 of 65/);
  for(const response of ['<html>Login</html>','MACT1\nERR\n',block(1),block(0).replace('0001','0002')]){
    requests=0;s=setup(async()=>{requests++;return {ok:true,text:async()=>response};});
    await s.elements.read.onclick();assert.equal(requests,1);assert.equal(s.elements.rows.children.length,0);assert.equal(s.elements.read.disabled,false);assert.match(s.elements.status.textContent,/0 complete blocks/);
  }
  console.log('UI checks passed: decoding, filtering, all 65 batches, login response, error/truncation, slot ordering.');
})().catch(e=>{console.error(e);process.exitCode=1});
