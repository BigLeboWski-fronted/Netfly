import React, { useState } from 'react';
export function Register({ request, onSuccess }) {
  const [values,setValues]=useState({}), [codeStep,setCodeStep]=useState(false), [busy,setBusy]=useState(false), [error,setError]=useState('');
  async function submit(event){
    event.preventDefault(); if(busy)return; setBusy(true);setError('');
    try {
      const body={email:values.email.trim(),username:values.username.trim(),password:values.password,...(codeStep?{code:values.code.trim()}:{})};
      const data=await request(codeStep?'/api/verify-code':'/api/send-code',{method:'POST',body:JSON.stringify(body)});
      if(codeStep){await onSuccess(data);setValues({});setCodeStep(false);}else setCodeStep(true);
    }catch(error){setError(error.message);}finally{setBusy(false);}
  }
  const fields=codeStep?[['code','Код подтверждения','text','one-time-code']]:[['email','Email','email','email'],['username','Имя пользователя','text','username'],['password','Пароль','password','new-password']];
  return <form onSubmit={submit} className="authFields"><fieldset disabled={busy} className="authReactFields">
    {codeStep&&<p className="small">Код отправлен на {values.email}</p>}
    {fields.map(([key,label,type,auto])=><div key={key}><label htmlFor={`register-${key}`}>{label}</label><input id={`register-${key}`} required type={type} autoComplete={auto} minLength={key==='password'?6:key==='username'?3:undefined} maxLength={key==='code'?6:key==='password'?72:80} value={values[key]||''} onChange={e=>setValues(v=>({...v,[key]:e.target.value}))}/></div>)}
    {error&&<p role="alert" className="authError">{error}</p>}
    <button type="submit" className="authSubmit">{busy?'Подождите…':codeStep?'Подтвердить':'Получить код'}</button>
    {codeStep&&<button type="button" onClick={()=>{setCodeStep(false);setError('');}}>Изменить данные</button>}
  </fieldset></form>;
}
