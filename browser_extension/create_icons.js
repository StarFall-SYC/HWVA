// 在浏览器中使用canvas创建简单的图标
// 由于我们不能直接创建图像文件，这个脚本会帮助用户生成图标

function createIcon(size) {
  const canvas = document.createElement('canvas');
  canvas.width = size;
  canvas.height = size;
  const ctx = canvas.getContext('2d');
  
  // 设置背景
  ctx.fillStyle = '#4285f4';
  ctx.beginPath();
  ctx.arc(size/2, size/2, size/2, 0, Math.PI * 2);
  ctx.fill();
  
  // 绘制保护盾牌形状
  ctx.fillStyle = '#ffffff';
  const shieldWidth = size * 0.6;
  const shieldHeight = size * 0.7;
  const shieldX = (size - shieldWidth) / 2;
  const shieldY = size * 0.15;
  
  // 盾牌上部
  ctx.beginPath();
  ctx.moveTo(shieldX, shieldY + shieldHeight * 0.3);
  ctx.lineTo(shieldX, shieldY);
  ctx.lineTo(shieldX + shieldWidth, shieldY);
  ctx.lineTo(shieldX + shieldWidth, shieldY + shieldHeight * 0.3);
  ctx.fill();
  
  // 盾牌下部
  ctx.beginPath();
  ctx.moveTo(shieldX, shieldY + shieldHeight * 0.3);
  ctx.lineTo(shieldX, shieldY + shieldHeight);
  ctx.lineTo(shieldX + shieldWidth/2, shieldY + shieldHeight * 1.1);
  ctx.lineTo(shieldX + shieldWidth, shieldY + shieldHeight);
  ctx.lineTo(shieldX + shieldWidth, shieldY + shieldHeight * 0.3);
  ctx.fill();
  
  // 绘制放大镜
  ctx.strokeStyle = '#4285f4';
  ctx.lineWidth = size * 0.08;
  
  // 放大镜圆圈
  ctx.beginPath();
  const magnifierSize = size * 0.25;
  const magnifierX = shieldX + shieldWidth * 0.35;
  const magnifierY = shieldY + shieldHeight * 0.45;
  ctx.arc(magnifierX, magnifierY, magnifierSize, 0, Math.PI * 2);
  ctx.stroke();
  
  // 放大镜手柄
  ctx.beginPath();
  const handleStartX = magnifierX + magnifierSize * 0.7;
  const handleStartY = magnifierY + magnifierSize * 0.7;
  const handleEndX = handleStartX + magnifierSize * 0.8;
  const handleEndY = handleStartY + magnifierSize * 0.8;
  ctx.moveTo(handleStartX, handleStartY);
  ctx.lineTo(handleEndX, handleEndY);
  ctx.stroke();
  
  return canvas.toDataURL('image/png');
}

// 生成不同尺寸的图标
const sizes = [16, 48, 128];
const icons = {};

sizes.forEach(size => {
  icons[size] = createIcon(size);
});

// 输出下载链接
console.log('请右键点击以下链接并保存为相应的图标文件:');
sizes.forEach(size => {
  console.log(`图标 ${size}x${size}:`, icons[size]);
}); 