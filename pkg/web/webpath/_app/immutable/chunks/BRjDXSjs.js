import"./DsnmJJEf.js";import{y as Y,v as ae,aA as re,ab as H,w as A,aB as ne,x as J,g as O,ap as oe,a8 as ve,a9 as de,aa as X,ac as L,C as I,aC as ce,aD as _e,z,B as he,aE as B,aF as F,A as me,aG as Z,ah as Ee,G as j,aH as te,S as pe,ae as Q,D as se,aI as Ne,aJ as V,J as we,aK as U,aL as ge,aM as Ae,aN as Te,aO as Ce,aP as Se,as as ie,E as be,aQ as xe,aR as Ie,aS as Me,p as De,K as ke,M as Re,b as $,c as He,d as Oe,s as Le,N as We,r as ye,L as ze,a as Be,u as Fe,aT as Ge}from"./CitxP-cn.js";import{i as Pe}from"./BWd9SBbi.js";import{a as ee}from"./DJ82hxZh.js";import{p as R,r as Ve}from"./CptUsCsW.js";function qe(s,a){return a}function Je(s,a,e){for(var t=s.items,o=[],c=a.length,i=0;i<c;i++)Te(a[i].e,o,!0);var _=c>0&&o.length===0&&e!==null;if(_){var m=e.parentNode;Ce(m),m.append(e),t.clear(),b(s,a[0].prev,a[c-1].next)}Se(o,()=>{for(var l=0;l<c;l++){var h=a[l];_||(t.delete(h.k),b(s,h.prev,h.next)),U(h.e,!_)}})}function Ke(s,a,e,t,o,c=null){var i=s,_={flags:a,items:new Map,first:null},m=(a&re)!==0;if(m){var l=s;i=A?H(ne(l)):l.appendChild(Y())}A&&J();var h=null,E=!1,v=new Map,T=oe(()=>{var p=e();return pe(p)?p:p==null?[]:te(p)}),r,d;function f(){Ye(d,r,_,v,i,o,a,t,e),c!==null&&(r.length===0?h?Q(h):h=z(()=>c(i)):h!==null&&se(h,()=>{h=null}))}ae(()=>{d??=ie,r=O(T);var p=r.length;if(E&&p===0)return;E=p===0;let N=!1;if(A){var C=ve(i)===de;C!==(p===0)&&(i=X(),H(i),L(!1),N=!0)}if(A){for(var x=null,w,n=0;n<p;n++){if(I.nodeType===ce&&I.data===_e){i=I,N=!0,L(!1);break}var u=r[n],g=t(u,n);w=K(I,_,x,null,u,g,n,o,a,e),_.items.set(g,w),x=w}p>0&&H(X())}if(A)p===0&&c&&(h=z(()=>c(i)));else if(he()){var D=new Set,W=me;for(n=0;n<p;n+=1){u=r[n],g=t(u,n);var M=_.items.get(g)??v.get(g);M?(a&(B|F))!==0&&le(M,u,n,a):(w=K(null,_,null,null,u,g,n,o,a,e,!0),v.set(g,w)),D.add(g)}for(const[S,y]of _.items)D.has(S)||W.skipped_effects.add(y.e);W.add_callback(f)}else f();N&&L(!0),O(T)}),A&&(i=I)}function Ye(s,a,e,t,o,c,i,_,m){var l=(i&ge)!==0,h=(i&(B|F))!==0,E=a.length,v=e.items,T=e.first,r=T,d,f=null,p,N=[],C=[],x,w,n,u;if(l)for(u=0;u<E;u+=1)x=a[u],w=_(x,u),n=v.get(w),n!==void 0&&(n.a?.measure(),(p??=new Set).add(n));for(u=0;u<E;u+=1){if(x=a[u],w=_(x,u),n=v.get(w),n===void 0){var g=t.get(w);if(g!==void 0){t.delete(w),v.set(w,g);var D=f?f.next:r;b(e,f,g),b(e,g,D),q(g,D,o),f=g}else{var W=r?r.e.nodes_start:o;f=K(W,e,f,f===null?e.first:f.next,x,w,u,c,i,m)}v.set(w,f),N=[],C=[],r=f.next;continue}if(h&&le(n,x,u,i),(n.e.f&V)!==0&&(Q(n.e),l&&(n.a?.unfix(),(p??=new Set).delete(n))),n!==r){if(d!==void 0&&d.has(n)){if(N.length<C.length){var M=C[0],S;f=M.prev;var y=N[0],G=N[N.length-1];for(S=0;S<N.length;S+=1)q(N[S],M,o);for(S=0;S<C.length;S+=1)d.delete(C[S]);b(e,y.prev,G.next),b(e,f,y),b(e,G,M),r=M,f=G,u-=1,N=[],C=[]}else d.delete(n),q(n,r,o),b(e,n.prev,n.next),b(e,n,f===null?e.first:f.next),b(e,f,n),f=n;continue}for(N=[],C=[];r!==null&&r.k!==w;)(r.e.f&V)===0&&(d??=new Set).add(r),C.push(r),r=r.next;if(r===null)continue;n=r}N.push(n),f=n,r=n.next}if(r!==null||d!==void 0){for(var k=d===void 0?[]:te(d);r!==null;)(r.e.f&V)===0&&k.push(r),r=r.next;var P=k.length;if(P>0){var fe=(i&re)!==0&&E===0?o:null;if(l){for(u=0;u<P;u+=1)k[u].a?.measure();for(u=0;u<P;u+=1)k[u].a?.fix()}Je(e,k,fe)}}l&&we(()=>{if(p!==void 0)for(n of p)n.a?.apply()}),s.first=e.first&&e.first.e,s.last=f&&f.e;for(var ue of t.values())U(ue.e);t.clear()}function le(s,a,e,t){(t&B)!==0&&Z(s.v,a),(t&F)!==0?Z(s.i,e):s.i=e}function K(s,a,e,t,o,c,i,_,m,l,h){var E=(m&B)!==0,v=(m&Ne)===0,T=E?v?Ee(o,!1,!1):j(o):o,r=(m&F)===0?i:j(i),d={i:r,v:T,k:c,a:null,e:null,prev:e,next:t};try{if(s===null){var f=document.createDocumentFragment();f.append(s=Y())}return d.e=z(()=>_(s,T,r,l),A),d.e.prev=e&&e.e,d.e.next=t&&t.e,e===null?h||(a.first=d):(e.next=d,e.e.next=d.e),t!==null&&(t.prev=d,t.e.prev=d.e),d}finally{}}function q(s,a,e){for(var t=s.next?s.next.e.nodes_start:e,o=a?a.e.nodes_start:e,c=s.e.nodes_start;c!==null&&c!==t;){var i=Ae(c);o.before(c),c=i}}function b(s,a,e){a===null?s.first=e:(a.next=e,a.e.next=e&&e.e),e!==null&&(e.prev=a,e.e.prev=a&&a.e)}function Qe(s,a,e,t,o,c){let i=A;A&&J();var _,m,l=null;A&&I.nodeType===xe&&(l=I,J());var h=A?I:s,E;ae(()=>{const v=a()||null;var T=e||v==="svg"?Ie:null;v!==_&&(E&&(v===null?se(E,()=>{E=null,m=null}):v===m?Q(E):U(E)),v&&v!==m&&(E=z(()=>{if(l=A?l:T?document.createElementNS(T,v):document.createElement(v),Me(l,l),t){A&&Pe(v)&&l.append(document.createComment(""));var r=A?ne(l):l.appendChild(Y());A&&(r===null?L(!1):H(r)),t(l,r)}ie.nodes_end=l,h.before(l)})),_=v,_&&(m=_))},be),i&&(L(!0),H(h))}/**
 * @license @lucide/svelte v0.544.0 - ISC
 *
 * ISC License
 * 
 * Copyright (c) for portions of Lucide are held by Cole Bemis 2013-2023 as part of Feather (MIT). All other copyright (c) for Lucide are held by Lucide Contributors 2025.
 * 
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 * 
 * ---
 * 
 * The MIT License (MIT) (for portions derived from Feather)
 * 
 * Copyright (c) 2013-2023 Cole Bemis
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 */const Ue={xmlns:"http://www.w3.org/2000/svg",width:24,height:24,viewBox:"0 0 24 24",fill:"none",stroke:"currentColor","stroke-width":2,"stroke-linecap":"round","stroke-linejoin":"round"};var Xe=ke("<svg><!><!></svg>");function ra(s,a){De(a,!0);const e=R(a,"color",3,"currentColor"),t=R(a,"size",3,24),o=R(a,"strokeWidth",3,2),c=R(a,"absoluteStrokeWidth",3,!1),i=R(a,"iconNode",19,()=>[]),_=Ve(a,["$$slots","$$events","$$legacy","name","color","size","strokeWidth","absoluteStrokeWidth","iconNode","children"]);var m=Xe();ee(m,E=>({...Ue,..._,width:t(),height:t(),stroke:e(),"stroke-width":E,class:["lucide-icon lucide",a.name&&`lucide-${a.name}`,a.class]}),[()=>c()?Number(o())*24/Number(t()):o()]);var l=Oe(m);Ke(l,17,i,qe,(E,v)=>{var T=Fe(()=>Ge(O(v),2));let r=()=>O(T)[0],d=()=>O(T)[1];var f=ze(),p=Be(f);Qe(p,r,!0,(N,C)=>{ee(N,()=>({...d()}))}),$(E,f)});var h=Le(l);Re(h,()=>a.children??We),ye(m),$(s,m),He()}export{ra as I,Ke as a,Qe as e,qe as i};
