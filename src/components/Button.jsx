import React from 'react';

const Button = ({ children, onClick, className = '', type = 'button', ...props }) => {
  return (
    <button
      type={type}
      className={`btn ${className}`}
      onClick={onClick}
      {...props}
    >
      {children}
    </button>
  );
};

export default Button;
