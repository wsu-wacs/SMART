%                             Copyright (C) <2017> 
%                        Mahdieh ZabihiMayvan, Reza Sadeghi   
%     Department of Computer Science and Engineering, Kno.e.sis Research Center, 
%                Wright State University, Dayton, OH, USA
% 
%     This program is free software: you can redistribute it and/or modify
%     it under the terms of the GNU General Public License as published by
%     the Free Software Foundation, either version 3 of the License, or
%     any later version.
% 
%     This program is distributed under the License on an "AS IS" BASIS,
%     but WITHOUT ANY WARRANTY; without even the implied warranty of
%     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
%     GNU General Public License for more details.
% 
%     You should have received a copy of the GNU General Public License
%     along with this program.  If not, see <http://www.gnu.org/licenses/>.
%
%     Using this code or any associated file of this package in a publication, 
%     please CITE the related paper as below:
%
%     Zabihimayvan, Mahdieh, Reza Sadeghi, H. Nathan Rude, and Derek Doran. 
%     "A Soft Computing Approach for Benign and Malicious Web Robot Detection." 
%     Expert Systems with Applications 87 (2017) 129-140.

%     If you have any questions concerning the implementation of the code, 
%     please feel free to contact us via email addresses below:

%     Zabhimayvan.2@wright.edu, mahdieh@knoesis.org, sadeghi.2@wright.edu,
%     reza@knoesis.org.


% X,Y are normalized
% AttributeType: 0->condition, 1->decision
% It is adapted to just numerical attributes with just one decision one

%Relation
%function [RC<-TC, RD<-TD]=Relation(X,Y,AttributeType)
function [TC, TD]=Relation(X,Y,AttributeType)

    DistanceCalculator=@(x,y) power((x-y),2);
    
    %1-Distance(x,y)
    Temp=find(AttributeType==0);% 0 -> condition attribute
    C=1-DistanceCalculator(X(Temp), Y(Temp));
    
    Temp=find(AttributeType==1);% 1 -> decision attribute
    D=1-DistanceCalculator(X(Temp), Y(Temp));

    %max(0,1-sigma(x,y))

    C(find(C<0))=0;

    D(find(D<0))=0;

    %T()
    switch numel(C)
        case 1
            TC=C(1);
        case 2
            TC=max(0,(C(1)+C(2)-1));
        otherwise
            TC=max(0,(C(1)+C(2)-1));
            for i=3:numel(C)
            TC=max(0,(TC+C(i)-1));
            end
    end

            TD=D(1);

end