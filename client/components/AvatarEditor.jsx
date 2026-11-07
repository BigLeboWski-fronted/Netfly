import React, { useRef, useState, useEffect } from 'react';

export function AvatarEditor({ onSave }) {
  const [source, setSource] = useState(null);
  const [zoom, setZoom] = useState(1);
  const [offset, setOffset] = useState({ x: 0, y: 0 });
  const [ratio, setRatio] = useState(1);
  const image = useRef(null), dialog = useRef(null), drag = useRef(null);
  useEffect(() => { if(source) dialog.current?.showModal(); }, [source]);
  const width = 280 * zoom * Math.max(1, ratio), height = width / ratio;
  const x = (280 - width)/2 + offset.x, y = (280-height)/2 + offset.y;
  const constrain = (position, scale = zoom) => {
    const w = 280 * scale * Math.max(1,ratio), h = w / ratio;
    return { x: Math.max(-(w-280)/2,Math.min((w-280)/2,position.x)), y: Math.max(-(h-280)/2,Math.min((h-280)/2,position.y)) };
  };
  function save() {
    const canvas = document.createElement('canvas'); canvas.width = canvas.height = 256;
    canvas.getContext('2d').drawImage(image.current, x*256/280, y*256/280, width*256/280, height*256/280);
    onSave(canvas.toDataURL('image/jpeg',.88)); setSource(null);
  }
  return <><label className="avatarUploadBtn">Загрузить<input type="file" accept="image/*" style={{ display:'none' }} onChange={event => {
    const file = event.target.files[0]; event.target.value = ''; if(!file) return;
    const reader = new FileReader(); reader.onload = () => { setZoom(1); setOffset({x:0,y:0}); setSource(reader.result); }; reader.readAsDataURL(file);
  }} /></label>
    {source && <dialog ref={dialog} className="deleteConfirm" onCancel={() => setSource(null)}><h3>Обрезать фото</h3>
      <div style={{width:280,height:280,position:'relative',overflow:'hidden',borderRadius:'50%',touchAction:'none',cursor:'grab'}} onPointerDown={event => { drag.current = {x:event.clientX-offset.x,y:event.clientY-offset.y}; event.currentTarget.setPointerCapture(event.pointerId); }} onPointerMove={event => { if(drag.current) setOffset(constrain({x:event.clientX-drag.current.x,y:event.clientY-drag.current.y})); }} onPointerUp={() => { drag.current=null; }} onPointerCancel={() => { drag.current=null; }}>
        <img ref={image} src={source} alt="Предпросмотр аватара" draggable={false} onLoad={event => setRatio(event.target.naturalWidth/event.target.naturalHeight)} style={{position:'absolute',maxWidth:'none',width,height,left:x,top:y}} />
      </div><label>Масштаб<input aria-label="Масштаб аватара" type="range" min="1" max="3" step=".01" value={zoom} onChange={event => { const value=Number(event.target.value); setZoom(value); setOffset(constrain(offset,value)); }} /></label>
      <div className="btns"><button type="button" onClick={() => setSource(null)}>Отмена</button><button type="button" className="primary" onClick={save}>Применить</button></div>
    </dialog>}
  </>;
}
