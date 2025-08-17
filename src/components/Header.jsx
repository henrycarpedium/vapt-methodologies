import React from 'react';

const Header = ({ title = 'My App', subtitle }) => {
  return (
    <header className="header">
      <h1>{title}</h1>
      {subtitle && <p>{subtitle}</p>}
    </header>
  );
};

export default Header;
